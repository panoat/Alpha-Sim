
// $Header: /cvsroot/nsnam/ns-2/apps/ping.h,v 1.5 2005/08/25 18:58:01 johnh Exp $


#ifndef ns_firewall_h
#define ns_firewall_h

#include "agent.h"
#include "tclcl.h"
#include "packet.h"
#include "address.h"
#include "tcp.h"
#include "ip.h"
#include "mac.h"

#define UP	1
#define DOWN	0
#define MARK	2

#define TH_FIN  0x01        /* FIN: closing a connection */
#define TH_SYN  0x02        /* SYN: starting a connection */
#define TH_RST	0x04
#define TH_PSH  0x08        /* PUSH: used here to "deliver" data */
#define TH_ACK  0x10        /* ACK: ack number is valid */
#define TH_URG	0x20

#define CLS_GD	0xA0		// 'Good' ip class
#define CLS_NT	0xA1		// 'Neutral' ip class
#define CLS_BD	0xA2		// 'Bad' ip class

#define	S1	1		// score increment for half-open connection
#define	S2	20		// score increment for timeout connection
#define	SDCY	1		// score decrement every TICK sec
#define SINIT	0		// initial score
#define SMAX	50		// maximum score

#define	T1	10		// timeout for 'good' clients (sec)
#define	T2	5		// timeout for 'neutral' clients (sec)
#define	TICK	1		// timeout for score decaying update

#define TH_NG	10		// neutral->good threshold score
#define	TH_GN	15		// good->neutral threshold score
#define	TH_BN	20		// bad->good threshold score
#define	TH_NB	25		// good->bad threshold score

#define HCT_NUM	((T1/TICK)+((T1%TICK==0)?0:1))	// hct array size
#define HCT_T2	((T2/TICK)+((T2%TICK==0)?0:1))	// index of T2 timeout slot

class FirewallAgent;

class FirewallTimer : public TimerHandler {

public:
	FirewallTimer( FirewallAgent* mgr) : TimerHandler(), mgr_(mgr) {}
	inline FirewallAgent* mgr() { return mgr_; }
protected:
	virtual void handle(Event* e);
	virtual void expire(Event* );
	FirewallAgent* mgr_;
};


class FirewallAgent : public Tap, public Agent {
public:
	FirewallAgent();
	~FirewallAgent();
	virtual int command(int argc, const char*const* argv);
	void recv(Packet*, Handler*);
	inline double now() {return Scheduler::instance().clock();}
	void timeout();

protected:
	FILE *outfp_;		// firewall log file
	FILE *hcfp_;		// half-open connection plotting file
	void tap(const Packet* p);
	void printPacket( Packet *pkt, FILE *out );
	const char *flagstr(int hflags);
	void update_hc( int dir );
	void send_spf(int saddr, int sport, int daddr, int dport, int flags, int seq, int ack);

	int enable_;			// enable observe only
	int enable_spf_;		// enable spoof packet sending
	int servip_;
	int hc_count_;
	FirewallTimer timer_;
	void print_ipct(void);
	void print_hct(void);
	inline const char* class_str(int cls) {
		switch (cls){
			case CLS_GD:	return "GOOD";
			case CLS_NT:	return "NEUTRAL";
			case CLS_BD:	return "BAD";
			default:	return "INVALID";
		}
	}

private:
	typedef struct ipct_dat_t
	{
		int score;
		int ipcls;

		ipct_dat_t(): 
			score(SINIT),
			ipcls((SINIT>TH_GN)?CLS_NT:CLS_GD) {}

		void update_score( int upd )		// score updating function
		{	score += (upd);					// update score
			score = (score < 0)?0:((score>SMAX)?SMAX:score);	// handling out-of-range

			if( upd < 0 )			// update in the "decreasing" hysteresis path
				ipcls = (score<TH_NG)?CLS_GD:((score<TH_NB)?CLS_NT:CLS_BD);
			else				// update in the "increasing" hysteresis path
				ipcls = (score>TH_NB)?CLS_BD:((score>TH_GN)?CLS_NT:CLS_GD);
		}

	} ipct_dat;

	typedef map<int, ipct_dat> ipct_tab;
	typedef map<string, int> hct_tab;

	ipct_tab ipct;			// IP Classifation table
	hct_tab hct[HCT_NUM];		// Half-open connection table array

	string hct_encap( int addr, int s_port, int d_port );
	int hct_decap( string ind, int opt );
};

#endif // ns_firewall_h
