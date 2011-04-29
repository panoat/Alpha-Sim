
// $Header: /cvsroot/nsnam/ns-2/apps/ping.h,v 1.5 2005/08/25 18:58:01 johnh Exp $


#ifndef ns_flooder_h
#define ns_flooder_h

#include "agent.h"
#include "timer-handler.h"

#include "tcp.h"
#include "ip.h"

#define FL_LSTN		0xA0	// listen state
#define FL_SRCV		0xA1	// syn-received state
#define FL_ESTB		0xA2	// established

#define FLMD_AT		0xB0	// attacker mode
#define FLMD_SV		0xB1	// server mode

#define INT_DET		0x00	// deterministic interval
#define INT_UNI		0x01	// uniform random interval
#define INT_PKM		0x02	// packmime random interval

#define RTO_INIT	3	// initial Syn/Ack retx timeout
#define RTO_MAX		60	// max Syn/Ack retx timeout
#define RTO_LIFE	500	// absolute timeout for Syn/Ack retx

#define HC_TIMEOUT	30	// half-open connection timeout

class RandomVariable;
class FlooderAgent;

class FloodTimer : public TimerHandler {
public:
	FloodTimer(FlooderAgent* fa) : fagent_(fa) {}
protected:
	virtual void handle(Event*);
	virtual void expire(Event*);
	FlooderAgent* fagent_;
};

class FloodAckTimer : public TimerHandler {
public:
	FloodAckTimer(FlooderAgent* fa) : fagent_(fa) {}
protected:
	virtual void handle(Event*);
	virtual void expire(Event*);
	FlooderAgent* fagent_;
};

class FlooderAgent : public Agent {
public:
	FlooderAgent();
	void init();
	void timeout();
	void ack_timeout();
	double next_interval(int&);
	inline void ustart() { start(); };
	inline void ustop() { stop(); };
	void reset();

	virtual int command(int argc, const char*const* argv);

protected:
	void start();
	void stop();
	void send_one();
	void recv(Packet*, Handler*);
	void finish();
	void send_resp( int flag );
	void atk_timeout();
	void srv_timeout();

 	int seqno_;
	int addr_;
	int port_;
	int state_;
	double nextPkttime_;
	double rate_;
	int random_;
	int spoofip_;
	double interval_;
	double ack_delay_;	// delay for 3rd ACK
	int maxpkts_;
	int numpkts_;
	int size_;
	int running_;
	FloodTimer timer_;
	FloodAckTimer ack_timer_;
	int mode_;
	int cur_rto_;		// current RTO for SYN/ACK
	int acc_rto_;		// accumulate RTO time

	//-- packmime variables --------
	int run_;
	RandomVariable* flowarrive_rv_;
	RNG* flowarrive_rng_;
	double flowarrive_rv_ir_mean_;
	double flowarrive_rv_ir_const_;

};



#endif // ns_flooder_h
