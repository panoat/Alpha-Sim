

#include "random.h"
#include "flooder.h"
#include "ranvar.h"
#include "packmime/packmime_ranvar.h"

#define TH_FIN  0x01        /* FIN: closing a connection */
#define TH_SYN  0x02        /* SYN: starting a connection */
#define TH_RST	0x04
#define TH_PSH  0x08        /* PUSH: used here to "deliver" data */
#define TH_ACK  0x10        /* ACK: ack number is valid */
#define TH_URG	0x20
#define BASE_HDR_SIZE	40

#define DBG(x)          printf("FLD-DEBUG: "#x"\n");
#define DBI(x)          printf("FLD-DEBUG: "#x" = %d\n", (x) );

static class FlooderClass : public TclClass {
public:
	FlooderClass() : TclClass("Agent/Flooder") {}
	TclObject* create(int, const char*const*) {
		return (new FlooderAgent());
	}
} class_flooder;


FlooderAgent::FlooderAgent() : Agent(PT_TCP), seqno_(0), addr_(0), port_(0),
				state_(FL_LSTN), nextPkttime_(-1), spoofip_(-1), 
				ack_delay_(-1), numpkts_(0), running_(0),
				timer_(this), ack_timer_(this), mode_(FLMD_SV), 
				cur_rto_(RTO_INIT), acc_rto_(0),
				run_(0), flowarrive_rv_(NULL),
				flowarrive_rng_(NULL),
				flowarrive_rv_ir_mean_(0),
				flowarrive_rv_ir_const_(1)
{
	bind("packetSize_", &size_);
	bind_bw("rate_", &rate_);
	bind("random_", &random_);
	bind("maxpkts_", &maxpkts_);
}


int FlooderAgent::command(int argc, const char*const* argv)
{
  	if (argc == 2) 
	{	if( strcmp(argv[1], "start-atk") == 0 ) {
			mode_ = FLMD_AT;
			start();
			return(TCL_OK);
		}
		else if( strcmp(argv[1], "start-srv") == 0 ) {
//DBG(start-srv)
			mode_ = FLMD_SV;
			start();
			return(TCL_OK);
		}
		else if( strcmp(argv[1], "stop") == 0 ) {
			stop();
			return(TCL_OK);
		}
		else if (strcmp(argv[1], "send-one") == 0) {
			mode_ = FLMD_AT;
			send_one();
      			return (TCL_OK);
    		}
  	}
	else if (argc == 3)
	{	if (strcmp(argv[1], "set-spoof-ip") == 0) {
			spoofip_ = (int) atoi (argv[2]);
      			return (TCL_OK);
    		}
		else if( strcmp(argv[1], "set-ackdelay") == 0) {
			ack_delay_ = (double) atof (argv[2]);
			return (TCL_OK);
		}
	}
  
	// If the command hasn't been processed by FlooderAgent()::command,
  	// call the command() function for the base class
  	return (Agent::command(argc, argv));
}


void FlooderAgent::init()
{
	int i;
	interval_ = (double)(size_ << 3)/(double)rate_;

	if(flowarrive_rv_ == NULL)
	{	flowarrive_rng_ = (RNG *) new RNG();
		for( i=0; i<run_; i++ )
			flowarrive_rng_->reset_next_substream();

		flowarrive_rv_ = (PackMimeHTTPFlowArriveRandomVariable*) new
			PackMimeHTTPFlowArriveRandomVariable( rate_, flowarrive_rng_);
	}
}


void FlooderAgent::start()
{
	init();
	running_ = 1;

	if( mode_ == FLMD_AT )
		atk_timeout();
}


void FlooderAgent::stop()
{
	if( !running_ )	return;

	timer_.force_cancel();
	//if( mode_ == FLMD_AT )
	//	ack_timer_.force_cancel();
	running_ = 0;
}


double FlooderAgent::next_interval(int& size)
{
	//interval_ = (double)(size_ << 3)/(double)rate_;
	interval_ = 1/(double)rate_;
	double t = interval_;

	if( random_ == INT_UNI )
		t += interval_ * Random::uniform( -0.5, 0.5 );
	else if( random_ == INT_PKM )
		t = flowarrive_rv_->value();

	size = size_;
	if( ++seqno_ < maxpkts_ )
		return(t);
	else return(-1);
}

void FlooderAgent::ack_timeout()
{
	send_resp( TH_ACK );	// send ACK response
	ack_timer_.cancel();	// only need 1 ACK
}

void FlooderAgent::timeout()
{
	switch( mode_ ) {
		case FLMD_AT:	atk_timeout();
				break;
		case FLMD_SV:	srv_timeout();
				break;
	}
}

void FlooderAgent::atk_timeout()
{
	if( !running_ ) return;

	send_one();
	nextPkttime_ = next_interval(size_);

	if( nextPkttime_ > 0 )
		timer_.resched(nextPkttime_);
	else running_ = 0;
}

void FlooderAgent::srv_timeout()
{
	if( !running_ ) return;

	send_resp( TH_ACK|TH_SYN );	// send SYN/ACK response

	if( acc_rto_ > RTO_LIFE )	// if reaching RTO_LIFE
	{	send_resp( TH_RST );	// send reset
		finish();		// terminate the connection
		return;
	}

	timer_.resched( cur_rto_ );
	acc_rto_ += cur_rto_;
	cur_rto_ = (cur_rto_*2 > RTO_MAX)?RTO_MAX:cur_rto_*2;
}

void FlooderAgent::send_one()
{
	Packet *pkt = allocpkt();	// packet to be sent
	hdr_tcp *tcph = HDR_TCP(pkt);	// access tcp header
	hdr_cmn *ch = HDR_CMN(pkt);	// access commone header
	hdr_ip *iph = HDR_IP(pkt);

	tcph->flags() = TH_SYN | TH_PSH;		// set SYN,PSH flag
	tcph->seqno() = 0;
	tcph->ackno() = -1;
	tcph->sa_length() = 0;
	tcph->hlen() = BASE_HDR_SIZE;
	ch->size() = tcph->hlen();
//	iph->sport() = (int)Random::uniform( 0.0, 30.0 );

	if( spoofip_ != -1 )
		iph->saddr() = spoofip_;

	if( ack_delay_ != -1 )		// start timer for 3rd ACK
		ack_timer_.resched( ack_delay_ );

	send( pkt, 0 );
	return;
}

void FlooderAgent::recv(Packet *pkt, Handler*)
{
	if(  !running_ || mode_ == FLMD_AT ) return;

	hdr_tcp *tcph = hdr_tcp::access(pkt);		// TCP header
	hdr_ip *iph = hdr_ip::access(pkt);		// IP header
	int flags = tcph->flags();

	if ( (flags & TH_SYN) && (state_ == FL_LSTN) )	// SYN packet receive
	{	
		seqno_ = tcph->seqno();		// record seq no.
		addr_ = iph->saddr();		// record IP for re-tx
		port_ = iph->sport();		// record port for re-tx
		
		// send SYN,ACK here
		state_ = FL_SRCV;		// change state to Syn-received
		timeout();			// send SYN/ACK & start re-tx
	}
	else if ( (flags & TH_ACK) && (state_ == FL_SRCV) )	// ACK receive
	{	state_ = FL_ESTB;
		// should end Flooder here.
		stop();
		finish();
	}
	else if ( flags & TH_RST )	// RST packet receive
	{ 	// terminate connection
		stop();
		finish();
	}
	return;
}

void FlooderAgent::send_resp( int flag )
{
	Packet *pkt = allocpkt();	// packet to be sent
	hdr_tcp *tcph = HDR_TCP(pkt);	// access tcp header
	hdr_cmn *ch = HDR_CMN(pkt);	// access commone header
	hdr_ip *iph = HDR_IP(pkt);
	tcph->seqno() = 1;		// for 3rd ACK

	if( mode_ == FLMD_SV )
	{	iph->daddr() = addr_;
		iph->dport() = port_;
		tcph->seqno() = 0;	// starting seq # always 0
	}

	tcph->ackno() = seqno_+1;
	tcph->flags() = (int)(flag|TH_PSH);	// reponse flag
	tcph->hlen() = BASE_HDR_SIZE;
	ch->size() = tcph->hlen();

	send(pkt, 0);
}

void FlooderAgent::reset()
{
	timer_.force_cancel();
	ack_timer_.force_cancel();

	seqno_ = 0;
	addr_ = 0;
	port_ = 0;
	state_ = FL_LSTN;
	nextPkttime_= -1; 
	spoofip_ = -1;
	running_ = 0;
	mode_ = FLMD_SV; 
	run_ = 0;
	cur_rto_ = RTO_INIT;
	acc_rto_ = 0;
	flowarrive_rv_ = NULL;
	flowarrive_rng_ = NULL;
	flowarrive_rv_ir_mean_ = 0;
	flowarrive_rv_ir_const_ = 1;
}

void FlooderAgent::finish()
{
	// call this after connection is closed
	Tcl::instance().evalf("%s done", this->name() );
}

//------- FLOODTIMER ----------------

void FloodTimer::expire(Event * = 0)
{

}
void FloodTimer::handle(Event* e)
{
	fagent_->timeout();
}

//------- FLOODACKTIMER ----------------

void FloodAckTimer::expire(Event * = 0)
{

}
void FloodAckTimer::handle(Event* e)
{
	fagent_->ack_timeout();
}
