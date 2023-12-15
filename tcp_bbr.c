/* Bottleneck Bandwidth and RTT (BBR) congestion control
 *
 * BBR congestion control computes the sending rate based on the delivery
 * rate (throughput) estimated from ACKs. In a nutshell:
 *
 *   On each ACK, update our model of the network path:
 *      bottleneck_bandwidth = windowed_max(delivered / elapsed, 10 round trips)
 *      min_rtt = windowed_min(rtt, 10 seconds)
 *   pacing_rate = pacing_gain * bottleneck_bandwidth
 *   cwnd = max(cwnd_gain * bottleneck_bandwidth * min_rtt, 4)
 *
 * The core algorithm does not react directly to packet losses or delays,
 * although BBR may adjust the size of next send per ACK when loss is
 * observed, or adjust the sending rate if it estimates there is a
 * traffic policer, in order to keep the drop rate reasonable.
 *
 * Here is a state transition diagram for BBR:
 *
 *             |
 *             V
 *    +---> STARTUP  ----+
 *    |        |         |
 *    |        V         |
 *    |      DRAIN   ----+
 *    |        |         |
 *    |        V         |
 *    +---> PROBE_BW ----+
 *    |      ^    |      |
 *    |      |    |      |
 *    |      +----+      |
 *    |                  |
 *    +---- PROBE_RTT <--+
 *
 * A BBR flow starts in STARTUP, and ramps up its sending rate quickly.
 * When it estimates the pipe is full, it enters DRAIN to drain the queue.
 * In steady state a BBR flow only uses PROBE_BW and PROBE_RTT.
 * A long-lived BBR flow spends the vast majority of its time remaining
 * (repeatedly) in PROBE_BW, fully probing and utilizing the pipe's bandwidth
 * in a fair manner, with a small, bounded queue. *If* a flow has been
 * continuously sending for the entire min_rtt window, and hasn't seen an RTT
 * sample that matches or decreases its min_rtt estimate for 10 seconds, then
 * it briefly enters PROBE_RTT to cut inflight to a minimum value to re-probe
 * the path's two-way propagation delay (min_rtt). When exiting PROBE_RTT, if
 * we estimated that we reached the full bw of the pipe then we enter PROBE_BW;
 * otherwise we enter STARTUP to try to fill the pipe.
 *
 * BBR is described in detail in:
 *   "BBR: Congestion-Based Congestion Control",
 *   Neal Cardwell, Yuchung Cheng, C. Stephen Gunn, Soheil Hassas Yeganeh,
 *   Van Jacobson. ACM Queue, Vol. 14 No. 5, September-October 2016.
 *
 * There is a public e-mail list for discussing BBR development and testing:
 *   https://groups.google.com/forum/#!forum/bbr-dev
 *
 * NOTE: BBR might be used with the fq qdisc ("man tc-fq") with pacing enabled,
 * otherwise TCP stack falls back to an internal pacing using one high
 * resolution timer per TCP socket and may use more resources.
 */
#include <linux/module.h>
#include <net/tcp.h>
#include <linux/inet_diag.h>
#include <linux/inet.h>
#include <linux/random.h>
#include <linux/win_minmax.h>

/* Scale factor for rate in pkt/uSec unit to avoid truncation in bandwidth
 * estimation. The rate unit ~= (1500 bytes / 1 usec / 2^24) ~= 715 bps.
 * This handles bandwidths from 0.06pps (715bps) to 256Mpps (3Tbps) in a u32.
 * Since the minimum window is >=4 packets, the lower bound isn't
 * an issue. The upper bound isn't an issue with existing technologies.
 */
#define BW_SCALE 24
#define BW_UNIT (1 << BW_SCALE)

#define BBR_SCALE 8	/* scaling factor for fractions in BBR (e.g. gains) */
#define BBR_UNIT (1 << BBR_SCALE)

/* BBR has the following modes for deciding how fast to send: */
enum bbr_mode {
	BBR_STARTUP,	/* ramp up sending rate rapidly to fill pipe */
	BBR_DRAIN,	/* drain any queue created during startup */
	BBR_PROBE_BW,	/* discover, share bw: pace around estimated bw */
	BBR_PROBE_RTT,	/* cut inflight to min to probe min_rtt */
};

/* BBR congestion control block */
struct bbr {
	u32	min_rtt_us;	        // 在 min_rtt_win_sec（10秒内） 的最小RTT
	u32	min_rtt_stamp;	        // 获取到min_rtt_us的时间戳（用来计算min_rtt是否过期(超过10s)）
	u32	probe_rtt_done_stamp;   // PROBE_RTT探测的结束时间
	struct minmax bw;	// 10个rtt内的最大bw。（是一个minmax变量，会记录一段时间内第1，2，3大的bw以及相应的时间（单位是pkts/uS，并且左移24位(<< 24)））
	u32	rtt_cnt;	    // 记录了已经经过的往返时间轮数（简单理解就是过了几轮RTT了）
	u32     next_rtt_delivered; // scb->tx.delivered at end of round
	u64	cycle_mstamp;	     // time of this cycle phase start
	u32     mode:3,		     // current bbr_mode in state machine
		prev_ca_state:3,     // 前一次ACK的ca状态
		packet_conservation:1,  // 遵循数据包守恒原则?
		round_start:1,	     // 表示一个往返开始的布尔值，即ACKs超过BBR.round_count。 // start of packet-timed tx->ack round?
		idle_restart:1,	     // 连接空闲后重新启动?
		probe_rtt_round_done:1,  // ProbeRTT模式下（inflight = 4 * cwnd）持续了1轮RTT？
		unused:13,
		lt_is_sampling:1,    // 是否正在长期采样
		lt_rtt_cnt:7,	     // 长期带宽采样的rtt轮数
		lt_use_bw:1;	     // 是否使用长期带宽采样(lt_bw)作为我们的bw估计?
	u32	lt_bw;		     	 // 长期带宽采样的传输速率(delivery_rate)，单位是pkts/uS，并经过左移24位
	u32	lt_last_delivered;   // 长期带宽采样开始时的delivered值（tp->delivered）
	u32	lt_last_stamp;	     // 长期带宽采样开始时的时间戳（tp->delivered_mstamp）
	u32	lt_last_lost;	     // 长期带宽采样开始时的丢包数（tp->lost）

	u32	pacing_gain:10,	// current gain for setting pacing rate
		cwnd_gain:10,	// current gain for setting cwnd
		full_bw_reached:1,   // 在Startup阶段时达到满bw ?
		full_bw_cnt:2,	// 连续rtt内，bw增长不超过25%的次数
		cycle_idx:3,	// current index in pacing_gain cycle array
		has_seen_rtt:1, // 我们看到RTT样本了吗?
		unused_b:5;
	u32	prior_cwnd;	// 上一次保存的"最佳"cwnd
	u32	full_bw;	// 最近的bw，用于估计管道是否已满

	// 用于跟踪ACK聚合:
	u64	ack_epoch_mstamp;	// ACK聚合采样周期的开始时间戳
	u16	extra_acked[2];		// 在采样周期中，ACKed的最大额外数据
	u32	ack_epoch_acked:20,	// 在采样周期中，ACKed的数据量
		extra_acked_win_rtts:5,	// extra_acked的时效，以往返数计(RTT)
		extra_acked_win_idx:1,	// extra_acked数组中的当前索引
		unused_c:6;
};

#define CYCLE_LEN	8	/* number of phases in a pacing gain cycle */

// bw过滤器窗口长度(以轮为单位):
static const int bbr_bw_rtts = CYCLE_LEN + 2;
// min_rtt过滤器的窗口长度(秒):
static const u32 bbr_min_rtt_win_sec = 10;
// 在BBR_PROBE_RTT模式下，最少持续时间（ms）
static const u32 bbr_probe_rtt_mode_ms = 200;
// 低于该带宽（单位bits/sec）以下，则跳过TSO：(1.2Mbps/s)
static const int bbr_min_tso_rate = 1200000;

/*
 * 为了减少瓶颈处的队列，平均速度要比估计的bw低1%。
 * 为了帮助推动网络走向更低的队列和低延迟，同时保持高利用率，平均pacing_rate的目标是略低于估计带宽。这是设计的一个重要方面。
 */
static const int bbr_pacing_margin_percent = 1;

// 发送速率的增益系数(2/ln(2) ~= 2.89)，也是Startup阶段的BBR.pacing_gain和BBR.cwnd_gain的最小增益。
static const int bbr_high_gain  = BBR_UNIT * 2885 / 1000 + 1; // 等于739

// Drain阶段的增益（是Startup阶段增益的倒数：1/high_gain）
static const int bbr_drain_gain = BBR_UNIT * 1000 / 2885;
// 为了应对对端的延迟/聚合ACK，在ProbeBW稳态下，cwnd增益为：
static const int bbr_cwnd_gain  = BBR_UNIT * 2;
// ProbeBW的增益数组
static const int bbr_pacing_gain[] = {
	BBR_UNIT * 5 / 4,	/* probe for more available bw */
	BBR_UNIT * 3 / 4,	/* drain queue and/or yield bw to other flows */
	BBR_UNIT, BBR_UNIT, BBR_UNIT,	/* cruise at 1.0*bw to utilize pipe, */
	BBR_UNIT, BBR_UNIT, BBR_UNIT	/* without creating excess queue... */
};
// 随机选择 N 个ProbeBW周期中的一个周期，作为开始增益循环阶段：
static const u32 bbr_cycle_rand = 7;

// ProbeRTT状态下的目标cwnd
static const u32 bbr_cwnd_min_target = 4;

// 如果bw显著增加(1.25倍)，则可能有更多的bw可用。（这是为了估计BBR_STARTUP模式（即high_gain）是否填满了管道）
static const u32 bbr_full_bw_thresh = BBR_UNIT * 5 / 4;
/* 经过3轮无显著增长后，估计管道已经满了: */
static const u32 bbr_full_bw_cnt = 3;

// -- 长期带宽采样所需的参数阈值 --
// 长期带宽采样的时间不得小于4个RTT：
static const u32 bbr_lt_intvl_min_rtts = 4;
// 如果丢包率(lost/delivered) >= 20%，那么这个采样周期内是“丢包的”，我们可能被限速了:
static const u32 bbr_lt_loss_thresh = 50;
// 如果2个连续采样的带宽比率小于等于1/8，则它们的bw是“一致的”:
static const u32 bbr_lt_bw_ratio = BBR_UNIT / 8;
// 如果两个采样周期的带宽速度差异小于等于4 Kbit/sec，则它们的bw是“一致的”:
static const u32 bbr_lt_bw_diff = 4000 / 8;
// lt_bw最多使用这么多次RTT，超过这个RTT次数后，就需要重新开始探测lt_bw
static const u32 bbr_lt_bw_max_rtts = 48;

// 将 extra_ackd 添加到目标cwnd的增益因子:
static const int bbr_extra_acked_gain = BBR_UNIT;
// extra_ack_window的窗口长度。
static const u32 bbr_extra_acked_win_rtts = 5;
/* ack_epoch_acked 的最大允许值，超过这个值后将重置采样时期。 */
static const u32 bbr_ack_epoch_acked_reset_thresh = 1U << 20;
// 由于ACK聚合而导致cwnd增加的时间段限制。
static const u32 bbr_extra_acked_max_us = 100 * 1000;

static void bbr_check_probe_rtt_done(struct sock *sk);

// 函数作用：判断是否跑满了bw
static bool bbr_full_bw_reached(const struct sock *sk)
{
	const struct bbr *bbr = inet_csk_ca(sk);

	return bbr->full_bw_reached;
}

// 函数作用：返回时间窗口内(10个RTT)最大的bw（单位为pkts/uS，并左移了24位(<< BW_SCALE)）
static u32 bbr_max_bw(const struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	return minmax_get(&bbr->bw);
}

// 函数作用：返回预估的bw（如果检测到被ISP限速，则返回限速后的bw，否则返回探测到的max_bw）。单位为pkts/uS，并左移了24位(<< BW_SCALE)
static u32 bbr_bw(const struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	return bbr->lt_use_bw ? bbr->lt_bw : bbr_max_bw(sk);
}

// 函数作用：返回过去 k-2k 轮的最大额外acked数，其中 k = bbr_extra_acked_win_rtts（bbr_extra_acked_win_rtts=5，也就是5-10个RTT内的最大值）。
static u16 bbr_extra_acked(const struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	return max(bbr->extra_acked[0], bbr->extra_acked[1]);
}

// 函数作用：返回以"字节/秒"为单位的rate。（使用bw和gain算出来后，还要乘以0.99，为了减少瓶颈处的队列）
// （tips：这里的顺序被精心选择以避免 u64 的溢出。 这应该适用于最高达 2.9Tbit/s 的输入速率和 2.89x 的增益。）
static u64 bbr_rate_bytes_per_sec(struct sock *sk, u64 rate, int gain)
{
	unsigned int mss = tcp_sk(sk)->mss_cache;

	rate *= mss;
	rate *= gain;
	rate >>= BBR_SCALE;
	rate *= USEC_PER_SEC / 100 * (100 - bbr_pacing_margin_percent); // 为了减少瓶颈处的队列，平均速度要比估计的bw低1%
	return rate >> BW_SCALE;
}

// 函数作用：将当前预估的bw和选择的增益gain，转换为"以字节每秒为单位"的pacing_rate。
static unsigned long bbr_bw_to_pacing_rate(struct sock *sk, u32 bw, int gain)
{
	u64 rate = bw;

	rate = bbr_rate_bytes_per_sec(sk, rate, gain);
	rate = min_t(u64, rate, sk->sk_max_pacing_rate);
	return rate;
}

// 函数作用：初始化pacing_rate为：(init_cwnd / RTT) * high_gain;
static void bbr_init_pacing_rate_from_rtt(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	u64 bw;
	u32 rtt_us;

	if (tp->srtt_us) {
		// 有平滑RTT样品了，转化为微秒后赋值给rtt_us，并设置has_seen_rtt=1（表示观察到rtt样本）
		rtt_us = max(tp->srtt_us >> 3, 1U);
		bbr->has_seen_rtt = 1;
	} else {
		// 还没有平滑RTT样本，则使用1000us作为默认值（1ms）
		rtt_us = USEC_PER_MSEC; // 1000us
	}
	bw = (u64)tp->snd_cwnd * BW_UNIT; // 初始时bw取init_cwnd（因为snd_cwnd在连接刚建立时就是使用的INIT_CWND初始化）

	// 初始的pacing_rate = (init_cwnd / RTT) * high_gain;
	do_div(bw, rtt_us);
	sk->sk_pacing_rate = bbr_bw_to_pacing_rate(sk, bw, bbr_high_gain);
}

// 函数作用：设置sk->sk_pacing_rate（使用当前BBR估计的bw和选择的增益gain计算新的pacing_rate）
static void bbr_set_pacing_rate(struct sock *sk, u32 bw, int gain)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	unsigned long rate = bbr_bw_to_pacing_rate(sk, bw, gain);

	// [如果BBR还没有获取到rtt样本 && 已经有了tcp平滑rtt值(srtt_us) ]，则：使用平滑rtt去初始化pacing_rate
	if (unlikely(!bbr->has_seen_rtt && tp->srtt_us))
		bbr_init_pacing_rate_from_rtt(sk);
	
	// [如果已经打满了带宽 || 新计算的pacing_rate > 当前pacing_rate]，则：更新pacing_rate
	if (bbr_full_bw_reached(sk) || rate > sk->sk_pacing_rate)
		sk->sk_pacing_rate = rate;
}

// 函数作用：返回bbr预期的最小tso分段数（覆盖sysctl_tcp_min_tso_segs）
static u32 bbr_min_tso_segs(struct sock *sk)
{
	return sk->sk_pacing_rate < (bbr_min_tso_rate >> 3) ? 1 : 2;
}

// 函数作用：计算BBR在传输过程中希望达到的 TSO (TCP Segmentation Offload) 的分段数目
static u32 bbr_tso_segs_goal(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 segs, bytes;

	// 计算一个分段的最大字节数 bytes。这个字节数受限于 pacing_rate 和 GSO_MAX_SIZE，并减去 TCP 报头的最大长度。
	// （类似于tcp_tso_autosize()，但忽略驱动程序提供的sk_gso_max_size）
	bytes = min_t(unsigned long,
		      sk->sk_pacing_rate >> READ_ONCE(sk->sk_pacing_shift),
		      GSO_MAX_SIZE - 1 - MAX_TCP_HEADER);

	// 计算期望的分段数目 segs，它是 bytes 除以 TCP 的 MSS 缓存大小的结果，但不得小于 bbr_min_tso_segs(sk)。
	segs = max_t(u32, bytes / tp->mss_cache, bbr_min_tso_segs(sk));

	return min(segs, 0x7FU);
}

// 函数作用：保存 “最后已知的最佳” cwnd，以便在 loss 或 PROBE_RTT 后恢复到最佳cwnd
static void bbr_save_cwnd(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);

	// [如果上一次ca状态不是处于recovery或loss状态 && BBR状态不是处于ProbeRTT]，则：以当前cwnd作为最佳cwnd保存
	if (bbr->prev_ca_state < TCP_CA_Recovery && bbr->mode != BBR_PROBE_RTT)
		bbr->prior_cwnd = tp->snd_cwnd;
	else  // [处于loss、recovery状态 或 ProbeRTT状态]，则 max(之前最佳cwnd, 当前cwnd)
		bbr->prior_cwnd = max(bbr->prior_cwnd, tp->snd_cwnd);
}

// 函数作用：在tcp协议栈发生cwnd事件时回调(可选) -- （BBR仅关注连接空闲重启事件）
static void bbr_cwnd_event(struct sock *sk, enum tcp_ca_event event)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);

	// [如果第一次发送数据包时，网络中没有之前发送的数据 && 处于应用程序限制状态]，则：认为是"连接空闲重启"，那么就需要执行BBR对于空闲重启的策略
	if (event == CA_EVENT_TX_START && tp->app_limited) {
		bbr->idle_restart = 1;

		// 1、如果是空闲重新启动，那么ack聚合探测器就要重置，重新开始进行ack聚合探测
		bbr->ack_epoch_mstamp = tp->tcp_mstamp;
		bbr->ack_epoch_acked = 0;
	
		// 2、为了避免无意义的缓冲区溢出，如果当前处于ProbeBW状态，则以估计的带宽作为pacing_rate，不附加额外增益。
		if (bbr->mode == BBR_PROBE_BW)
			bbr_set_pacing_rate(sk, bbr_bw(sk), BBR_UNIT);
		else if (bbr->mode == BBR_PROBE_RTT) // 如果当前处于ProbeRTT模式，则马上进行判断是否需要结束ProbeRTT了
			bbr_check_probe_rtt_done(sk);
	}
}

// 函数作用：根据 min_rtt 和 max_bw 计算 BDP（可附加增益gain）
static u32 bbr_bdp(struct sock *sk, u32 bw, int gain)
{
	struct bbr *bbr = inet_csk_ca(sk);
	u32 bdp;
	u64 w;

	// 还没有采集到有效RTT，则使用TCP初始窗口
	if (unlikely(bbr->min_rtt_us == ~0U))
		return TCP_INIT_CWND; // 做成可配置

	w = (u64)bw * bbr->min_rtt_us;

	// 对给定的值应用增益gain，去除 BW_SCALE 移位，并将该值四舍五入以避免负反馈循环。
	bdp = (((w * gain) >> BBR_SCALE) + BW_UNIT - 1) / BW_UNIT;

	return bdp;
}

/* 函数作用：为了在高速网络中实现最佳性能，对cwnd做了一些额外补充（补充内容：bbr_tso的3倍 + 向上四舍五入到下一个偶数(减少延迟ack) + ProbeBW模式下+2）
 * 
 * 为了在高速网络路径上实现最佳性能，我们通过为 cwnd 预算足够的空间，以便在两个对端系统上都能容纳全尺寸的 skbs 以充分利用路径，考虑以下这种情况：
 *   -- 1个 skb 在发送主机的 Qdisc 中
 *   -- 1个 skb 在发送主机的 TSO/GSO 引擎中
 *   -- 1个 skb 正在接收主机的 LRO/GRO/delayed-ACK 引擎中。
 * 对于低速率（bbr_min_tso_rate），这不会使 cwnd 膨胀，因为在这种情况下 tso_segs_goal 为 1。
 * 最小的 cwnd 是 4 个数据包，这允许两个未完成的 2个数据包序列，以尽量保持管道打满，即使存在每隔一个数据包的延迟ACK。
 */
static u32 bbr_quantization_budget(struct sock *sk, u32 cwnd)
{
	struct bbr *bbr = inet_csk_ca(sk);

	// 允许足够的全尺寸 skb 在 flight 中，以充分利用端系统。
	// 将cwnd增加3倍的bbr-TSO，以容纳三个完整大小的skb。这3个skb分别位于上述描述的Qdisc、TSO引擎中。（这样做可以确保在整个网络路径上都有足够的数据在传输）
	cwnd += 3 * bbr_tso_segs_goal(sk);

	// 通过将cwnd四舍五入到下一个偶数来减少延迟的ack。
	cwnd = (cwnd + 1) & ~1U;

	// 即使对于小的BDP，也要确保增益循环高于BDP。
	if (bbr->mode == BBR_PROBE_BW && bbr->cycle_idx == 0)
		cwnd += 2;

	return cwnd;
}

// 函数作用：根据min_rtt和 max_bw计算出BDP，然后把BDP作为BBR的目标inflight；
//（最终返回的inflight = BDP * 当前pacing_gain + bbr_quantization_budget额外的cwnd增益）
static u32 bbr_inflight(struct sock *sk, u32 bw, int gain)
{
	u32 inflight;

	inflight = bbr_bdp(sk, bw, gain);
	inflight = bbr_quantization_budget(sk, inflight); // 为cwnd加上一些策略的额外增益

	return inflight;
}

/* 函数作用：根据EDT决策，估计已经发送到网络中的数据包数量。
 * 
 * TSQ：TCP 发送队列(Transmission Send Queue)。 
 *  	BBR在计算传输中的数据量（inflight）时，会考虑加上TSO中的数据。这是因为在TSQ中的数据虽然尚未被发送到网络，但它们已经进入了发送队列，
 *		可能会在稍后的时间被发送出去。因此，BBR在计算inflight时会考虑了TSQ中的数据，以更准确地估算网络中的数据包数量。
 * 
 * EDT：最早离开时间(Earliest Departure Time)
 * 		它表示 TCP 数据包在传输过程中的最早可能离开时间。BBR使用 EDT 来进行数据包的排队和发送控制。
 * 		具体来说，当一个 TCP 数据包被放入发送队列（TSQ）时，BBR会计算该数据包的EDT。BBR根据这个 EDT 信息来调整数据包的发送时间，以更好地利用网络带宽，同时避免过多的排队延迟。
 * 
 * 函数原注释：
 * 		使用底层pacing时，“真实还在网络中传输的数据” 通常少于 “inflight”数据
 * 		由于TSQ和pacing time在较低的层(例如fq)，我们通常有几个skb在pacing层中排队，它们具有预先安排的最早出发时间（EDT）。
 * 		BBR 根据其估计的inflight调整其pacing rate，该inflight的估计已经“计入”了之前的出发时间决定。
 * 		我们粗略估计下一个 skb 计划的最早出发时间时，网络中可能存在的数据包数量：
 * 			in_network_at_edt = inflight_at_edt - (EDT - now) * bw
 * 		如果我们增加 inflight，那么我们想知道 EDT skb 的发送是否会将 inflight 增大至超过我们的预期，因此 inflight_at_edt 包括来自于 EDT 时刻发送的 skb 的 bbr_tso_segs_goal()。
 * 		如果减少inflight，则估计在 EDT 发送之前 inflight 是否会下降得太低。
 */
static u32 bbr_packets_in_net_at_edt(struct sock *sk, u32 inflight_now)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	u64 now_ns, edt_ns, interval_us;
	u32 interval_delivered, inflight_at_edt;

	now_ns = tp->tcp_clock_cache; // 当前时间
	edt_ns = max(tp->tcp_wstamp_ns, now_ns); // 下一个数据的发送时间
	interval_us = div_u64(edt_ns - now_ns, NSEC_PER_USEC); // 当前时间距下次发包的间隔
	interval_delivered = (u64)bbr_bw(sk) * interval_us >> BW_SCALE; // 这个间隔预期能发多少数据
	inflight_at_edt = inflight_now;

	// 如果pacing_gain > 1.0（在超发阶段），那么为inflight增加bbr预期的TSO分段数
	if (bbr->pacing_gain > BBR_UNIT)
		inflight_at_edt += bbr_tso_segs_goal(sk);  // 包括了待发送的EDT skb

	if (interval_delivered >= inflight_at_edt)
		return 0;
	return inflight_at_edt - interval_delivered;
}

// 函数作用：根据对"ACKed聚合"的估计找到 cwnd 增量
static u32 bbr_ack_aggregation_cwnd(struct sock *sk)
{
	u32 max_aggr_cwnd, aggr_cwnd = 0;

	// 如果跑满了bw，那么就计算因为ack聚合导致的cwnd需要增大多少
	if (bbr_extra_acked_gain && bbr_full_bw_reached(sk)) {
		max_aggr_cwnd = ((u64)bbr_bw(sk) * bbr_extra_acked_max_us) / BW_UNIT;
		aggr_cwnd = (bbr_extra_acked_gain * bbr_extra_acked(sk)) >> BBR_SCALE;
		aggr_cwnd = min(aggr_cwnd, max_aggr_cwnd);
	}

	return aggr_cwnd;
}

/* 函数作用：根据连接是处于"丢包恢复(Recovery)"，还是从丢包恢复状态恢复到正常状态了：来决定cwnd的值为多少。
 *        	丢包恢复(Recovery)状态下：cwnd遵循包守恒，即收到多少acked增加多少；
 *			结束丢包恢复状态：cwnd恢复到之前保存的"最佳"cwnd
 *
 * 函数原注释：
 * 	  BBR中的一项优化以减少丢包：在恢复的第一轮中，我们遵循数据包保守原则：每P个被确认的数据包发送P个数据包。
 * 	  在此之后，我们进行慢启动，并且每P个被确认的数据包最多发送2*P个数据包。
 * 	  恢复完成后，或在撤销时，我们还原恢复开始时的cwnd（受估算的BDP基于目标cwnd的限制）。
 * 	  TODO（ycheng/ncardwell）：实现基于速率的方法。
 */
static bool bbr_set_cwnd_to_recover_or_restore(
	struct sock *sk, const struct rate_sample *rs, u32 acked, u32 *new_cwnd)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	u8 prev_state = bbr->prev_ca_state, state = inet_csk(sk)->icsk_ca_state;
	u32 cwnd = tp->snd_cwnd;

	// 如果有丢包情况，则根据丢包数适当减少当前拥塞窗口大小，后续cwnd会在 bbr_set_cwnd() 中恢复。（ 这是为了在丢包恢复期间有效地控制发送速率，以避免再次触发丢包。）
	if (rs->losses > 0)
		cwnd = max_t(s32, cwnd - rs->losses, 1);

	// 进入Recovery阶段的第一轮时，遵循"数据包守恒原则"
	if (state == TCP_CA_Recovery && prev_state != TCP_CA_Recovery) {
		bbr->packet_conservation = 1; // 遵循数据包守恒原则
		bbr->next_rtt_delivered = tp->delivered;  // 开始新的一轮RTT计数
		cwnd = tcp_packets_in_flight(tp) + acked; // 包守恒原则，cwnd增加acked的数量
	} // 退出丢包恢复状态了
	else if (prev_state >= TCP_CA_Recovery && state < TCP_CA_Recovery) {
		cwnd = max(cwnd, bbr->prior_cwnd); // 退出丢包恢复，恢复到之前保存的最佳cwnd。
		bbr->packet_conservation = 0; // 不在遵循包守恒
	}
	bbr->prev_ca_state = state;

	// 如果遵循包守恒原则，那么cwnd最多为 inflight + acked
	if (bbr->packet_conservation) {
		*new_cwnd = max(cwnd, tcp_packets_in_flight(tp) + acked);
		return true;	/* yes, using packet conservation */
	}

	// 不遵循包守恒原则，则new_cwnd为BBR策略计算出来的cwnd
	*new_cwnd = cwnd;
	return false;
}

/* 函数作用：设置tcp的cwnd。（根据多种策略，如：是否(处于/结束)Recover状态、cwnd补偿、是否已跑满带宽、cwnd的运行范围等等）（简单概括：就是加性增，减性乘）。
 *		（后续优化：如果后续分析中发现cwnd是BBR的瓶颈点，那么就来对这个函数进行优化，一定能解决cwnd的瓶颈问题）
 *原注释：
 *	如果带宽bw正在增长，或者由于丢包导致cwnd降低，那么我们通过慢启动向目标cwnd缓慢靠近；
 *	如果当前cwnd在目标cwnd之上，则快速减少cwnd到目标cwnd。
 */
static void bbr_set_cwnd(struct sock *sk, const struct rate_sample *rs,
			 u32 acked, u32 bw, int gain)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	u32 cwnd = tp->snd_cwnd, target_cwnd = 0;

	// 当前ack包中没有新确认的数据
	if (!acked)
		goto done;

	// 1、根据是否(处于/结束)Recover状态，来判断要不要遵循包守恒原则。遵循的话，则直接到done
	if (bbr_set_cwnd_to_recover_or_restore(sk, rs, acked, &cwnd))
		goto done;

	// bbr的目标cwnd（即BDP）
	target_cwnd = bbr_bdp(sk, bw, gain);

	// 2、对cwnd进行补偿
	// 增加cwnd，以应对ack聚合情况
	target_cwnd += bbr_ack_aggregation_cwnd(sk);
	// 增加cwnd，为了在高速网络中实现最佳性能
	target_cwnd = bbr_quantization_budget(sk, target_cwnd);

	// 3、根据是否跑满bw，决定cwnd(增加/减少)策略
	// 如果当前已经跑满了bw
	if (bbr_full_bw_reached(sk))
		cwnd = min(cwnd + acked, target_cwnd); // 跑满带宽bw的情况下，如果超过目标cwnd，则强制减少为目标cwnd
	// 没跑满带宽为前提的情况下，如果[当前cwnd < 目标cwnd || 已交付的数据包 < TCP首窗]，则通过慢启动将cwnd向目标cwnd移动（cwnd每次只增加acked数）
	else if (cwnd < target_cwnd || tp->delivered < TCP_INIT_CWND)
		cwnd = cwnd + acked; // 没跑满cwnd的情况下，缓慢增加cwnd到目标cwnd

	// 4、确保cwnd在[4,snd_cwnd_clamp]范围内
	// cwnd最低不小于4个
	cwnd = max(cwnd, bbr_cwnd_min_target);

done:
	// 确保cwnd不会超过snd_cwnd_clamp
	tp->snd_cwnd = min(cwnd, tp->snd_cwnd_clamp);

	// 如果当前是ProbeRTT模式，那么需确保cwnd不会超过4
	if (bbr->mode == BBR_PROBE_RTT)
		tp->snd_cwnd = min(tp->snd_cwnd, bbr_cwnd_min_target);
}

// 函数作用：判断是否结束当前的ProbeBW周期（判断如果到达了一个RTT，或我们达到了相应的inflight目标，则结束当前PROBE_BW周期）
static bool bbr_is_next_cycle_phase(struct sock *sk,
				    const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	// 是否过去了一个RTT（当前acked时间 - 当前周期进入的时间 > min_rtt）
	bool is_full_length = tcp_stamp_us_delta(tp->delivered_mstamp, bbr->cycle_mstamp) > bbr->min_rtt_us;
	u32 inflight, bw;

	// 1、pacing_gain == 1.0 时，以估计的带宽进行pacing
	// -- 判断离开该阶段条件：是否过去了一个RTT
	if (bbr->pacing_gain == BBR_UNIT)
		return is_full_length;

	// 根据EDT决策，估计已经发送到网络中的数据包数量。
	inflight = bbr_packets_in_net_at_edt(sk, rs->prior_in_flight);
	bw = bbr_max_bw(sk);

	// 2、pacing_gain > 1.0 时，通过尝试将inflight提高到 pacing_gain * BDP 来探测是否有更大的bw;
	// -- 判断离开该阶段条件：（过了一个RTT && (发生过丢包 || 发送的inflight已经达到目标inflight))
	if (bbr->pacing_gain > BBR_UNIT)
		return is_full_length &&
			(rs->losses ||  /* perhaps pacing_gain*BDP won't fit */
			 inflight >= bbr_inflight(sk, bw, bbr->pacing_gain));

	// 3、pacing_gain < 1.0时，如果bw探测没有找到更多的bw，则该阶段会尝试耗尽我们添加的额外队列。
	// -- 判断离开该阶段条件：(是否过去了一个RTT || 发送的inflight <= 目标inflight)
	return is_full_length ||
		inflight <= bbr_inflight(sk, bw, BBR_UNIT);
}

// 函数作用：循环往前推进ProbeBW周期，并更新进入该周期的时间cycle_mstamp
static void bbr_advance_cycle_phase(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);

	bbr->cycle_idx = (bbr->cycle_idx + 1) & (CYCLE_LEN - 1);
	bbr->cycle_mstamp = tp->delivered_mstamp;
}

// 函数作用：判断并更新ProbeBW周期。（循环调整pacing_gain，以收敛到可用带宽的公平份额。）
static void bbr_update_cycle_phase(struct sock *sk,
				   const struct rate_sample *rs)
{
	struct bbr *bbr = inet_csk_ca(sk);

	// 如果当前是PROBE_BW状态，并且到达进入下一个周期的条件，则进入下个PROBE_BW周期。
	if (bbr->mode == BBR_PROBE_BW && bbr_is_next_cycle_phase(sk, rs))
		bbr_advance_cycle_phase(sk);
}

// 函数作用：强制进入Startup状态
static void bbr_reset_startup_mode(struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	bbr->mode = BBR_STARTUP;
}

// 函数作用：强制进入ProbeBW状态，并随机从8个增益周期中挑选一个，用该随机值的下一个作为当前增益周期
static void bbr_reset_probe_bw_mode(struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	bbr->mode = BBR_PROBE_BW;
	bbr->cycle_idx = CYCLE_LEN - 1 - prandom_u32_max(bbr_cycle_rand);
	bbr_advance_cycle_phase(sk);
}

// 函数作用：根据是否打满带宽，判断是进入Startup还是ProbeBW状态
static void bbr_reset_mode(struct sock *sk)
{
	if (!bbr_full_bw_reached(sk)) // 未跑满带宽，进入Startup阶段，快速增长
		bbr_reset_startup_mode(sk);
	else
		bbr_reset_probe_bw_mode(sk); // 打满带宽，进入ProbeBW阶段
}

// 函数作用：重置长期带宽采样相关参数，以开始一个新的长期带宽采样周期。
//（主要是记录本轮长期带宽采样刚开始时的时间戳、丢包数lost、delivered数据量，并设置采样rtt轮数为0） 
static void bbr_reset_lt_bw_sampling_interval(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);

	bbr->lt_last_stamp = div_u64(tp->delivered_mstamp, USEC_PER_MSEC); // 单位从us转换到ms
	// 记录长期采样的delivered、last_lost（后面用结束值减去该值，来计算采样数据）
	bbr->lt_last_delivered = tp->delivered;
	bbr->lt_last_lost = tp->lost;
	bbr->lt_rtt_cnt = 0;
}

// 函数作用：重置长期带宽的采样lt_bw，为进行新一轮的长期带宽采样做准备。（lt是long-term的意思）【ISP的令牌桶策略检测】
static void bbr_reset_lt_bw_sampling(struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	bbr->lt_bw = 0; // 长期采样的带宽
	bbr->lt_use_bw = 0; // 是否使用长期采样的带宽
	bbr->lt_is_sampling = false; // 是否在长期采样

	// 重置长期带宽采样相关参数，以开始一个新的长期带宽采样周期。
	bbr_reset_lt_bw_sampling_interval(sk);
}

// 函数作用：使用连续的2次长期带宽采样值进行判断，判断我们是否受到了ISP的令牌桶限速策略，如果我们判断是被ISP限速了的话，那么就使用这2次采样的平均值作为我们全局的预估bw，以尽量避免丢包。
//			(判断是否被ISP限速的条件：[如果连续两次长期带宽采样的变化小于等于12.5% || 连续两次长期带宽采样的速率变化小于等于 4Kbit/sec]，则认为我们被限速了)
static void bbr_lt_bw_interval_done(struct sock *sk, u32 bw)
{
	struct bbr *bbr = inet_csk_ca(sk);
	u32 diff;

	// 我们之前已经采样到了一个lt_bw值：
	if (bbr->lt_bw) {
		diff = abs(bw - bbr->lt_bw); // 当前采样的lt_bw和之前采样到的lt_bw的差值
		// [如果当前采样的lt_bw和之前采样的lt_bw变化比例小于12.5% || 两个采样周期的速率变化小于 4Kbit/sec]，则：认为带宽是稳定的了(有ISP限速)，那么就启用长期采样带宽lt_bw的值作为当前预估的bw。
		if ((diff * BBR_UNIT <= bbr_lt_bw_ratio * bbr->lt_bw) ||
		    (bbr_rate_bytes_per_sec(sk, diff, BBR_UNIT) <= bbr_lt_bw_diff)) {
			// 符合所有标准，认为我们受到了限速，开始使用长期采样带宽lt_bw的值作为我们全局预估的bw
			bbr->lt_bw = (bw + bbr->lt_bw) >> 1;  // lt_bw = 2次采样的平均值
			bbr->lt_use_bw = 1;
			bbr->pacing_gain = BBR_UNIT;  // 不使用额外pacing_gain增益，尝试避免丢包
			bbr->lt_rtt_cnt = 0;
			return;
		}
	}

	// 第一次采样到长期带宽的值，先记录下来。 用于后续第二次长期采样结束后，比对两个采样带宽值变化是否不大，如果变化不大，则认为被ISP限速了，那么就使用采样到的lt_bw作为后续的预估bw
	bbr->lt_bw = bw;
	// 重置长期带宽采样的相关参数，以便于后续新一轮的采样
	bbr_reset_lt_bw_sampling_interval(sk);
}

/* 函数作用：开始进行长期带宽采样，并根据各种限定条件（①②③④⑤⑥）过滤不符合条件的采样数据，然后把采样到的数据进行判断，判断是否存在ISP限速，如果存在的话，那么就把采样到的限速值作为全局bw。
 *			（判断是否被ISP限速的条件见：bbr_lt_bw_interval_done()）
 * 原注释：
 *	 令牌桶流量监管是常见的(参见“互联网范围内的流量监管分析”，SIGCOMM 2016)。BBR检测令牌桶策略并显式地对其策略率进行建模，以减少不必要的丢包。
 *	 我们估计，如果我们看到连续2个采样间隔具有一致的"吞吐量" 和 "高丢包"，那就表示我们受到ISP限速。
 *	 如果我们认为受到了限制，那么将lt_bw设置为这两个间隔的"长期"平均delivery_rate。
 */
static void bbr_lt_bw_sampling(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	u32 lost, delivered;
	u64 bw;
	u32 t;

	/* --- 1、确保长期带宽采样的lt_bw只会被使用48个RTT，超过48次则需要重新进行采样 --- */
	// 已经在使用lt_bw的情况下：[如果当前模式是ProbeBW && 新一轮的RTT开始 && lt_rtt_cnt >= 48次]，则：重置长期带宽采样结果，进行新一轮的长期采样。重置ProbeBW的周期。
	if (bbr->lt_use_bw) {
		if (bbr->mode == BBR_PROBE_BW && bbr->round_start &&
		    ++bbr->lt_rtt_cnt >= bbr_lt_bw_max_rtts) {
			bbr_reset_lt_bw_sampling(sk);
			bbr_reset_probe_bw_mode(sk);
		}
		return;
	}

	/* --- 2、开始进行采样，需判断本次采样数据是否符合要求。----
	 *	要求：① 发生第一次丢包才开始进行采样；② 当前rs采样不能存在应用程序限制；③ 一个长期带宽采样周期必须保持在[4,16]个RTT内，超过16次则重新开始采样；④ 每次采样的rs中必须有丢包；
	 		 ⑤ 每次采样的rs中必须有数据到达；⑥ 仅采样丢包率超过20%以后的数据；
	 */
	// ① 在开始采样之前等待第一个丢包，以便让ISP耗尽其令牌并估算允许的稳态令牌生成速率。（否则，如果较早开始采样的话，采样值会偏大，因为bw前期没被限速时会较大）
	if (!bbr->lt_is_sampling) { // 还没开始采样
		if (!rs->losses) // 没有丢包就直接返回，直到遇到第一次丢包才开始采样
			return;

		// 出现第一次丢包了，那么就开始进行采样。把当前时间作为采样周期的开始。
		bbr_reset_lt_bw_sampling_interval(sk);
		bbr->lt_is_sampling = true;
	}

	// ② 为了避免低估采样的带宽，因此如果当前是应用程序限制，则重新开始采样
	if (rs->is_app_limited) {
		bbr_reset_lt_bw_sampling(sk);
		return;
	}

	// 一个新的RTT轮次开始，那么就增加本次采样周期内的RTT轮数
	if (bbr->round_start)
		bbr->lt_rtt_cnt++;
	
	// ③ 长期带宽采样周期的时间范围必须是[4,16]个RTT内，超过该时间范围则需重新开始采样
	if (bbr->lt_rtt_cnt < bbr_lt_intvl_min_rtts) // 采样周期太短（小于4个RTT），则延长采样时间
		return;
	if (bbr->lt_rtt_cnt > 4 * bbr_lt_intvl_min_rtts) { // 采样周期太长（大于16个RTT），则重新开始采样
		bbr_reset_lt_bw_sampling(sk);
		return;
	}

	// ④ 没有丢包，不采样（如果采样未丢包的数据，可能会导致采样到的lt_bw偏低，因为还没打满令牌桶）
	if (!rs->losses)
		return;

	// 计算在采样间隔内的"丢包数" 和 "交付数(成功传输的acked数)"。
	lost = tp->lost - bbr->lt_last_lost;
	delivered = tp->delivered - bbr->lt_last_delivered;

	// ⑤⑥ [如果没有数据到达 || 丢包率不超过20%(50/256)]，则：无视这次采样，继续等待新数据到达 && 丢包率超过20%
	// (丢包率计算方式：(lost/delivered) >= lt_loss_thresh(20%))
	if (!delivered || (lost << BBR_SCALE) < bbr_lt_loss_thresh * delivered)
		return;

	/* --- 3、计算采样时间内的平均交付速率(delivery_rate)，并判断是否被ISP限速了，如果判断出来被限速了，那么就使用2次采样的lt_bw平均值作为全局预估的bw使用 --- */
	t = div_u64(tp->delivered_mstamp, USEC_PER_MSEC) - bbr->lt_last_stamp; // 采样的时间（单位ms）
	if ((s32)t < 1) // 采样时间小于1毫秒，忽略本次采样，等待更多的采样
		return;
	if (t >= ~0U / USEC_PER_MSEC) { // 检测后续转换为us时，是否会溢出。(如果会溢出的话，说明采样时间太久了，则重新开始采样)
		bbr_reset_lt_bw_sampling(sk);
		return;
	}
	t *= USEC_PER_MSEC; // 转换为us单位

	// 计算采样时间内的平均交付速率(delivery_rate)
	bw = (u64)delivered * BW_UNIT;
	do_div(bw, t);
	// 一个长期带宽采样的周期结束，就根据采样值去判断是否被ISP限速了，如果判断出来被限速了的话，那么就使用2次采样的平均值作为全局预估的bw使用
	bbr_lt_bw_interval_done(sk, bw);
}

// 函数作用：根据rs采样的数据包的交付速度(delivered / interval_us)估算带宽bw。（bw有效期：10个rtt窗口内）
static void bbr_update_bw(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	u64 bw;

	// 初始化round_start，表示当前不处于一个新的RTT的开始
	bbr->round_start = 0;
	if (rs->delivered < 0 || rs->interval_us <= 0) // rs采样数据无效
		return;

	// 检测是否到了下一个RTT（rs采样的最后一次delivered数据量，大于bbr下一个rtt周期到达的数据量，就说明一个rtt周期已经走完了）
	if (!before(rs->prior_delivered, bbr->next_rtt_delivered)) {
		bbr->next_rtt_delivered = tp->delivered; // bbr下一个rtt的到达量（就是当前tcp总共收到的acked量）
		bbr->rtt_cnt++;
		bbr->round_start = 1; // 标识新的RTT开始
		bbr->packet_conservation = 0; // 不使用包守恒定律
	}

	// 进行长期带宽采样（为了检测是否有ISP的令牌桶限速策略）
	bbr_lt_bw_sampling(sk, rs);

	// 将delivered除以interval以找到bw的"下界"。(delivered以数据包为单位，interval以微秒为单位)
	// (对于大多数连接，比率将远小于1。因此，首先对delivered进行缩放。)
	bw = div64_long((u64)rs->delivered * BW_UNIT, rs->interval_us);

	// 如果样本不是应用程序限制（app-limited），或者样本的带宽大于等于最大带宽，那么就将新样本纳入“最大带宽过滤器”中
	if (!rs->is_app_limited || bw >= bbr_max_bw(sk)) {
		// 更新最大bw（10个rtt窗口内）
		minmax_running_max(&bbr->bw, bbr_bw_rtts, bbr->rtt_cnt, bw);
	}
}

/* 函数作用：估算最大的ACK聚合程度，用于提供额外的 inflight，以便在 ACK 静默期间保持发送。（确认聚合的程度：是根据超出预期的额外acked进行估计的。）
 * 
 * 原注释：
 * 		max_extra_acked = "最近超过max_bw之外的acked数据量 * interval"
 * 		cwnd += max_extra_acked
 *
 * 		最大extra_acked受到cwnd和bw * bbr_extra_acked_max_us（100毫秒）的限制。
 * 		最大过滤器是一个大约为5-10（以数据包计时）往返的滑动窗口。
 */
static void bbr_update_ack_aggregation(struct sock *sk,
				       const struct rate_sample *rs)
{
	u32 epoch_us, expected_acked, extra_acked;
	struct bbr *bbr = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	// 确保计算ACK聚合的前提条件满足
	if (!bbr_extra_acked_gain || rs->acked_sacked <= 0 ||
	    rs->delivered < 0 || rs->interval_us <= 0)
		return;

	// 一个新的发送轮次的开始
	if (bbr->round_start) {
		// 一个新的rtt周期，那么extra_acked的窗口时效也要更新
		bbr->extra_acked_win_rtts = min(0x1F, bbr->extra_acked_win_rtts + 1);

		// 当extra_acked_win_rtts时效过期（超过5个RTT）
		if (bbr->extra_acked_win_rtts >= bbr_extra_acked_win_rtts) {
			bbr->extra_acked_win_rtts = 0;
			// 二进制索引切换（eg：当前idx=0，就切换idx到1，并且清空1对应的值为0）
			// （作用：一个extra_acked只能保持5个rtt能的最大值，而我们需要保存5-10个rtt的extra_acked）
			bbr->extra_acked_win_idx = bbr->extra_acked_win_idx ? 0 : 1;
			bbr->extra_acked[bbr->extra_acked_win_idx] = 0;
		}
	}

	// 计算在一个周期内，我们期望收到多少个acked（期望值 = bw * epoch_us）
	epoch_us = tcp_stamp_us_delta(tp->delivered_mstamp, bbr->ack_epoch_mstamp);
	expected_acked = ((u64)bbr_bw(sk) * epoch_us) / BW_UNIT;

	// 如果ACK速率低于预期速率 或 自检测时期以来已接收到大量ACK超过阈值（可能是持续了很久的采样周期），则重置聚合时期。
	if (bbr->ack_epoch_acked <= expected_acked ||
	    (bbr->ack_epoch_acked + rs->acked_sacked >= bbr_ack_epoch_acked_reset_thresh)) {
		bbr->ack_epoch_acked = 0;
		bbr->ack_epoch_mstamp = tp->delivered_mstamp;
		expected_acked = 0;
	}

	// 计算超出预期的额外的acked数量（extra_acked）
	bbr->ack_epoch_acked = min_t(u32, 0xFFFFF, bbr->ack_epoch_acked + rs->acked_sacked);
	extra_acked = bbr->ack_epoch_acked - expected_acked;
	extra_acked = min(extra_acked, tp->snd_cwnd);
	if (extra_acked > bbr->extra_acked[bbr->extra_acked_win_idx])
		bbr->extra_acked[bbr->extra_acked_win_idx] = extra_acked;
}

// 函数作用：检测3个rtt内，bw增长是否不超过25%，不超过的话，说明当前已经打满带宽了。（不分状态，无论任何任何状态下，只要bw增长不达预期，则认为打满带宽了）
static void bbr_check_full_bw_reached(struct sock *sk,
				      const struct rate_sample *rs)
{
	struct bbr *bbr = inet_csk_ca(sk);
	u32 bw_thresh;

	if (bbr_full_bw_reached(sk) || !bbr->round_start || rs->is_app_limited)
		return;

	// 当前的bw * 1.25
	bw_thresh = (u64)bbr->full_bw * bbr_full_bw_thresh >> BBR_SCALE;

	// 检测到更大的bw，那么就更新对应的参数
	if (bbr_max_bw(sk) >= bw_thresh) {
		bbr->full_bw = bbr_max_bw(sk);
		bbr->full_bw_cnt = 0;
		return;
	}

	// 累加bw增长不超过25%的次数，达到3次的话，则将full_bw_reached置位true，标志则当前已经打满带宽
	++bbr->full_bw_cnt;
	bbr->full_bw_reached = bbr->full_bw_cnt >= bbr_full_bw_cnt;
}

// 函数作用：判断是否进入drain阶段，和判断是否可以离开drain阶段。
static void bbr_check_drain(struct sock *sk, const struct rate_sample *rs)
{
	struct bbr *bbr = inet_csk_ca(sk);

	// [如果当前处于Startup阶段 && 已经打满带宽了]，那么则进入drain阶段。同时更新ssthresh = BBR目标的inflight
	if (bbr->mode == BBR_STARTUP && bbr_full_bw_reached(sk)) {
		bbr->mode = BBR_DRAIN;
		// 设置ssthresh，仅仅只是为了SCM_TIMESTAMPING_OPT_STATS能检查BBR是否退出了Startup阶段，对BBR实际运转没有影响
		tcp_sk(sk)->snd_ssthresh = bbr_inflight(sk, bbr_max_bw(sk), BBR_UNIT);
	}

	// [如果当前处于drain阶段 && 实际inflight < BBR的目标inflight]，那么则进入ProbeBW阶段
	if (bbr->mode == BBR_DRAIN &&
	    bbr_packets_in_net_at_edt(sk, tcp_packets_in_flight(tcp_sk(sk))) <=
	    bbr_inflight(sk, bbr_max_bw(sk), BBR_UNIT)) {
			bbr_reset_probe_bw_mode(sk);
		}
}

// 函数作用：判断是否结束ProbeRTT阶段，并进入下一个状态（Startup或ProbeBW），具体根据是否打满带宽(full_bw_reached)来判断进入哪一状态
static void bbr_check_probe_rtt_done(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);

	// ProbeRTT还没有持续超过200ms，则直接返回。（判断条件：!当前时间已经超过probe_rtt_done_stamp）
	if (!(bbr->probe_rtt_done_stamp && after(tcp_jiffies32, bbr->probe_rtt_done_stamp)))
		return;

	// 结束ProbeRTT状态后，则认为当前已经获取到min_rtt了，那么需要更新min_rtt_stamp，以便于判断下次进入ProbeRTT的时间（当前时间的10s后)）
	bbr->min_rtt_stamp = tcp_jiffies32;

	// 恢复cwnd到之前保存的"最佳"cwnd（因为ProbeRTT阶段，把cwnd减少到4个，需要恢复到之前高速状态）
	tp->snd_cwnd = max(tp->snd_cwnd, bbr->prior_cwnd);

	// 进入Startup 或 ProbeBW状态（根据是否打满带宽(full_bw_reached)来判断）
	bbr_reset_mode(sk);
}

// 函数作用：更新min_rtt。 如果min_rtt超过10s没有更新，则强制进入ProbeRTT状态，并且该函数也会检测ProbeRTT状态是否应该结束（ProbeRTT结束后，根据带宽是否打满判断，自动进入下一对应状态）
static void bbr_update_min_rtt(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	bool filter_expired;

	// 当前min_rtt是否过期（超过10s）
	filter_expired = after(tcp_jiffies32, bbr->min_rtt_stamp + bbr_min_rtt_win_sec * HZ);

	/* 
	 * 在当前rs采样的rtt有效的前提下，下列两种情况下更新min_rtt为当前最新采样的rtt：
	 * 	1、最新采样rtt < min_rtt;
	 * 	2、min_rtt已经过期，并且当前采样的ack不是延迟ack;
	 */
	if (rs->rtt_us >= 0 &&
	    (rs->rtt_us < bbr->min_rtt_us ||
	     (filter_expired && !rs->is_ack_delayed))) {
		bbr->min_rtt_us = rs->rtt_us;
		bbr->min_rtt_stamp = tcp_jiffies32;
	}

	// [如果min_rtt已过期 && 不是空闲重启 && 当前模式不是ProbeRTT]，则：保存当前cwnd后进入ProbeRTT状态（空闲重启后，一定会不会进入ProbeRTT状态）
	if (bbr_probe_rtt_mode_ms > 0 && filter_expired &&
	    !bbr->idle_restart && bbr->mode != BBR_PROBE_RTT) {
		bbr->mode = BBR_PROBE_RTT;
		bbr_save_cwnd(sk);  // 记录下当前cwnd，以便退出ProbeRTT后可以恢复到当前cwnd
		bbr->probe_rtt_done_stamp = 0;
	}

	if (bbr->mode == BBR_PROBE_RTT) {
		// 在ProbeRTT中忽略低速率采样。
		tp->app_limited = (tp->delivered + tcp_packets_in_flight(tp)) ? : 1;

		// [如果ProbeRTT还没开始 && 传输中的数据包 < 4个cwnd]，则开始进入ProbeRTT状态
		// （ProbeRTT状态至少要维持 max(200毫秒,1个rtt)）
		if (!bbr->probe_rtt_done_stamp && tcp_packets_in_flight(tp) <= bbr_cwnd_min_target) {
			bbr->probe_rtt_done_stamp = tcp_jiffies32 + msecs_to_jiffies(bbr_probe_rtt_mode_ms); // ProbeRTT的结束时间（200ms后）
			bbr->probe_rtt_round_done = 0; // 是否过去了一个RTT
			bbr->next_rtt_delivered = tp->delivered; // 下一个RTT的判断条件（见bbr_update_bw函数）
		} else if (bbr->probe_rtt_done_stamp) { // 如果已经在ProbeRTT真实探测阶段内了（probe_rtt_done_stamp != 0）
			// 过去了1个RTT了
			if (bbr->round_start)
				bbr->probe_rtt_round_done = 1;
			
			// 过去了1个RTT了，那么接着需要检测ProbeRTT是否持续超过200ms了。（因为ProbeRTT要求持续时间最少是：max(200毫秒,1个rtt)）
			// 如果ProbeRTT状态可以结束的话，并会根据是否打满带宽来判断进入哪一个状态（Startup或ProbeBW）
			if (bbr->probe_rtt_round_done)
				bbr_check_probe_rtt_done(sk);
		}
	}
	// 收到新的ack数据了，退出idle_restart状态
	if (rs->delivered > 0)
		bbr->idle_restart = 0;
}

// 函数作用：根据BBR所处的不同状态，选择不同的gain系数
static void bbr_update_gains(struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	switch (bbr->mode) {
	case BBR_STARTUP:
		// Startup阶段：pacing_gain和cwnd_gain都用最高增益系数(2/ln2 = 2.885)，以让Startup阶段的带宽能够指数级增长
		bbr->pacing_gain = bbr_high_gain;
		bbr->cwnd_gain	 = bbr_high_gain;
		break;
	case BBR_DRAIN:
		// Drain阶段：pacing_gain用Startup阶段增益的倒数（ln2/2 = 0.346），以让Drain阶段更快的排空Startup阶段超发造成的队列
		//			 cwnd_gain保持最高增益
		bbr->pacing_gain = bbr_drain_gain;
		bbr->cwnd_gain	 = bbr_high_gain;
		break;
	case BBR_PROBE_BW:
		// ProbeBW阶段：如果检测到ISP限速，那么pacing_gain就为1。 否则pacing_gain取当前增益数组(bbr_pacing_gain)中对应的值
		//			   cwnd_gain保持为2（意思是目标inflight = 2 * BDP。 这是为了应对ACK的延迟和聚合）
		bbr->pacing_gain = (bbr->lt_use_bw ? BBR_UNIT : bbr_pacing_gain[bbr->cycle_idx]);
		bbr->cwnd_gain	 = bbr_cwnd_gain;
		break;
	case BBR_PROBE_RTT:
		// ProbeRTT阶段：pacing_gain和cwnd_gain都为1（相当于没有增益的正常发送）
		bbr->pacing_gain = BBR_UNIT;
		bbr->cwnd_gain	 = BBR_UNIT;
		break;
	default:
		WARN_ONCE(1, "BBR bad mode: %u\n", bbr->mode);
		break;
	}
}

// rate_sample作用：测量时间间隔“interval_us” 内 “已传输(delivered)”的（原始/重传）数据包的数量。
//  （如果“delivered”或“interval_us”为负数，则样本无效。）
static void bbr_update_model(struct sock *sk, const struct rate_sample *rs)
{
	bbr_update_bw(sk, rs); // 根据采样，更新实时的bw
	bbr_update_ack_aggregation(sk, rs); // 计算由于ack聚合导致的额外多接收了多少acked，用于后续作为cwnd的增益补偿
	bbr_update_cycle_phase(sk, rs); // 如果在PROBE_BW状态下，检测并进入循环周期下一个阶段
	bbr_check_full_bw_reached(sk, rs); // 判断是否跑满了bw，跑满的话则将full_bw_reached置为true
	bbr_check_drain(sk, rs); // 判断是否进入drain阶段，和判断是否可以离开drain阶段
	bbr_update_min_rtt(sk, rs); // 根据采样，更新最小rtt，如果rtt长时间不变，进入probe_rtt阶段
	bbr_update_gains(sk); // 根据BBR所处的不同状态，选择不同的gain系数
}

static void bbr_main(struct sock *sk, const struct rate_sample *rs)
{
	struct bbr *bbr = inet_csk_ca(sk);
	u32 bw;

	// 更新bbr模型（主要就是更新bbr的参数，如：bw, min_rtt, BBR的状态机，对应的gain系数等）
	bbr_update_model(sk, rs);

	// bbr预估的当前带宽
	bw = bbr_bw(sk);

	// 根据当前预估的bw和选择的pacing_gain，去设置sk->sk_pacing_rate
	bbr_set_pacing_rate(sk, bw, bbr->pacing_gain);

	// 设置tcp的cwnd。（根据多种策略来设置，如：是否(处于/结束)Recover状态、cwnd补偿、是否已跑满带宽、cwnd的运行范围等等）（简单概括：就是加性增，减性乘）
	bbr_set_cwnd(sk, rs, rs->acked_sacked, bw, bbr->cwnd_gain);
}

static void bbr_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);

	bbr->prior_cwnd = 0;
	tp->snd_ssthresh = TCP_INFINITE_SSTHRESH;
	bbr->rtt_cnt = 0;
	bbr->next_rtt_delivered = tp->delivered;
	bbr->prev_ca_state = TCP_CA_Open;
	bbr->packet_conservation = 0;

	bbr->probe_rtt_done_stamp = 0;
	bbr->probe_rtt_round_done = 0;
	bbr->min_rtt_us = tcp_min_rtt(tp); // 初始化时，先从tcp_sock中获取当前min_rtt（通常是从三次握手包中获取到）
	bbr->min_rtt_stamp = tcp_jiffies32; // 获取到min_rtt的时间

	minmax_reset(&bbr->bw, bbr->rtt_cnt, 0);  /* init max bw to 0 */

	bbr->has_seen_rtt = 0;
	bbr_init_pacing_rate_from_rtt(sk); // 通过三次握手中的rtt 和 init_cwnd，去初始化pacing_rate

	bbr->round_start = 0;
	bbr->idle_restart = 0;
	bbr->full_bw_reached = 0;
	bbr->full_bw = 0;
	bbr->full_bw_cnt = 0;
	bbr->cycle_mstamp = 0;
	bbr->cycle_idx = 0;
	bbr_reset_lt_bw_sampling(sk); // 重置长期带宽的采样（采样是为了检测是否被“ISP的令牌桶策略”限速了）
	bbr_reset_startup_mode(sk); // 重置BBR模式为BBR_STARTUP状态

	// 用于跟踪ACK聚合相关的变量初始化：
	bbr->ack_epoch_mstamp = tp->tcp_mstamp;
	bbr->ack_epoch_acked = 0;
	bbr->extra_acked_win_rtts = 0;
	bbr->extra_acked_win_idx = 0;
	bbr->extra_acked[0] = 0;
	bbr->extra_acked[1] = 0;

	// 设置BBR必须使用pacing。（如果不使用FQ，那么就会使用TCP协议栈内部自实现的pacing，但是可能会导致CPU升高）
	cmpxchg(&sk->sk_pacing_status, SK_PACING_NONE, SK_PACING_NEEDED);
}

static u32 bbr_sndbuf_expand(struct sock *sk)
{
	// 扩大3倍cwnd(默认2倍)，因为即使在recovery期间，BBR也可能会进行慢启动（Startup阶段）。
	return 3;
}

/* 函数作用：tcp协议栈撤销cwnd的减少时的回调函数（函数内主要工作：①重置带宽是否打满的判断； ②重置长期带宽的采样；）
 * 
 * 原注释：理论上，BBR不需要撤销cwnd，因为它在发生丢包时并不总是减小cwnd（参见bbr_main()）。先留着吧。
 */
static u32 bbr_undo_cwnd(struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	// 把当前检测到的bw和打满bw的次数都置为0，用于重置之前带宽是否打满的检测结果，重新进行带宽是否打满的判断。
	//（注意：这只会造成"虚假的减速"，因为在下个RTT到来时，一定会调用bbr_check_full_bw_reached()进行检测带宽是否打满。
	//		 而由于max_bw保存了最大bw，因此BDP并不会减小，只是会重新进行是否打满带宽的判断）
	bbr->full_bw = 0;
	bbr->full_bw_cnt = 0;

	// 重置长期带宽的采样。（用于检测是否存在ISP令牌桶限速情况）
	bbr_reset_lt_bw_sampling(sk);

	// 返回当前的cwnd（因为BBR不会像CUBIC那样猛烈的减少cwnd，通常cwnd都保持在一个良好值，因此仅返回当前实时的cwnd即可）
	return tcp_sk(sk)->snd_cwnd;
}

// 函数作用：返回当前的sshthresh（对BBR没有什么作用，只是必须实现该回调，可忽略）
static u32 bbr_ssthresh(struct sock *sk)
{
	bbr_save_cwnd(sk);
	return tcp_sk(sk)->snd_ssthresh;
}

// 函数作用：获取当前连接的BBR拥塞控制变量信息
static size_t bbr_get_info(struct sock *sk, u32 ext, int *attr,
			   union tcp_cc_info *info)
{
	if (ext & (1 << (INET_DIAG_BBRINFO - 1)) ||
	    ext & (1 << (INET_DIAG_VEGASINFO - 1))) {
		struct tcp_sock *tp = tcp_sk(sk);
		struct bbr *bbr = inet_csk_ca(sk);
		u64 bw = bbr_bw(sk);

		bw = bw * tp->mss_cache * USEC_PER_SEC >> BW_SCALE;
		memset(&info->bbr, 0, sizeof(info->bbr));
		info->bbr.bbr_bw_lo		= (u32)bw;
		info->bbr.bbr_bw_hi		= (u32)(bw >> 32);
		info->bbr.bbr_min_rtt		= bbr->min_rtt_us;
		info->bbr.bbr_pacing_gain	= bbr->pacing_gain;
		info->bbr.bbr_cwnd_gain		= bbr->cwnd_gain;
		*attr = INET_DIAG_BBRINFO;
		return sizeof(info->bbr);
	}
	return 0;
}

// 函数作用：tcp协议栈在更改ca_state之前的回调。（BBR只关注loss丢包状态，忽略了其他ca状态变化。在loss丢包状态下，BBR每次都会调用长期带宽采样函数进行采样，并判断是否被ISP令牌桶限速了）
static void bbr_set_state(struct sock *sk, u8 new_state)
{
	struct bbr *bbr = inet_csk_ca(sk);

	if (new_state == TCP_CA_Loss) {
		struct rate_sample rs = { .losses = 1 };

		bbr->prev_ca_state = TCP_CA_Loss;
		bbr->full_bw = 0;
		bbr->round_start = 1;	// 把RTO当作一个回合的结束
		// 每次RTO都会触发长期带宽采样，然后根据采样结果，判断是否存在被ISP限速了，如果被ISP限速了，那么就使用我们探测到的限速值作为全局的bw
		bbr_lt_bw_sampling(sk, &rs);
	}
}

static struct tcp_congestion_ops tcp_bbr_cong_ops __read_mostly = {
	.flags		= TCP_CONG_NON_RESTRICTED,
	.name		= "bbr",
	.owner		= THIS_MODULE,
	.init		= bbr_init, // 初始化私有数据(可选) -- 初始化拥塞控制的私有数据(也就是inet_csk_ca返回的)，该函数是在tcp_init_congestion_control中被调用，通常是在连接刚建立时调用(进行ca的初始化)
	.cong_control	= bbr_main, // 在完成所有ca_state处理后，在发送数据包时调用以更新cwnd和pacing rate。(可选) -- 拥塞控制的主逻辑
	.sndbuf_expand	= bbr_sndbuf_expand, // 返回tcp_sndbuf_expand中使用的乘数(可选) -- 缓冲区扩大的倍数(默认2，BBR是3)
	.undo_cwnd	= bbr_undo_cwnd, // 撤销cwnd的减少(必选) -- CUBIC中是返回当前cwnd和之前保存cwnd最大值
	.cwnd_event	= bbr_cwnd_event, /* 发生cwnd事件时调用(可选) -- 事件主要由tcp_ca_event内声明的事件。
								  	BBR只处理CA_EVENT_TX_START事件(可理解为屏蔽了其他事件)，该事件触发条件：当发送一个数据包时，如果网络中无发送且未确认的数据包，则触发此事件。
									该事件通常是在连接刚建立 或 空闲一段时间后触发。
								  */
	.ssthresh	= bbr_ssthresh, // 返回慢启动阈值(必选) -- 查看linux内核源代码，发现只有在loss、cwr、recover中会调用该函数，结合bbr_ssthresh函数，可侧面验证。
	.min_tso_segs	= bbr_min_tso_segs, // 覆盖sysctl_tcp_min_tso_segs(可选) -- 覆盖获取最小TCP分段数函数，用于确定最小的TCP分段数。
	.get_info	= bbr_get_info, // 获取inet_diag的信息(可选) -- 获取拥塞控制相关信息函数，用于获取拥塞控制算法的状态信息。
	.set_state	= bbr_set_state, // 在更改ca_state之前调用(可选) -- 每次ca状态改变时调用该函数(BBR只关注loss状态)
};

static int __init bbr_register(void)
{
	BUILD_BUG_ON(sizeof(struct bbr) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&tcp_bbr_cong_ops);
}

static void __exit bbr_unregister(void)
{
	tcp_unregister_congestion_control(&tcp_bbr_cong_ops);
}

module_init(bbr_register);
module_exit(bbr_unregister);

MODULE_AUTHOR("Van Jacobson <vanj@google.com>");
MODULE_AUTHOR("Neal Cardwell <ncardwell@google.com>");
MODULE_AUTHOR("Yuchung Cheng <ycheng@google.com>");
MODULE_AUTHOR("Soheil Hassas Yeganeh <soheil@google.com>");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("TCP BBR (Bottleneck Bandwidth and RTT)");
