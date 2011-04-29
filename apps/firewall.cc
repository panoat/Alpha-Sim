
#include <string>
#include <map>
#include "firewall.h"

#define DBG(x) 		printf( "FW-DEBUG: "#x"\n");
#define DBI(x)		printf( "FW-DEBUG: "#x" = %d\n", x );

static class FirewallClass : public TclClass {
public:
	FirewallClass() : TclClass("Agent/Firewall") {}
	TclObject* create(int, const char*const*) {
		return (new FirewallAgent());
	}
} class_firewall;


FirewallAgent::FirewallAgent() : Agent(PT_TCP), outfp_(NULL), hcfp_(NULL),
				enable_(0), enable_spf_(0),
				servip_(-1), hc_count_(0),timer_(this)
{

	// binding
}

FirewallAgent::~FirewallAgent()
{
	timer_.force_cancel();

	ipct.clear();				// clear IPCT table
	for( int i = 0; i < HCT_NUM; i++ )	// clear all HCT tables
		hct[i].clear();

	if( outfp_ )
		fclose( outfp_ );
	if( hcfp_ )
		fclose( hcfp_ );
}

int FirewallAgent::command(int argc, const char*const* argv)
{
	TclObject *obj;

	if (argc == 2)
	{	if ( strcmp(argv[1], "enable") == 0 ) {
			enable_ = 1;
			enable_spf_ = 0;
			update_hc(MARK);
			timer_.sched(0);		// start timer
			return(TCL_OK);
		}
		else if( strcmp(argv[1], "enable-spoof") == 0 ) {
			enable_spf_ = 1;
			enable_ = 1;
			update_hc(MARK);
			timer_.sched(0);		// start timer
			return(TCL_OK);
		}
		else if( strcmp(argv[1], "disable") == 0 ) {
			enable_ = 0;
			enable_spf_ = 0;
			timer_.force_cancel();
			return(TCL_OK);
		}
	}
  	else if (argc == 3) {
		if (strcasecmp(argv[1], "set-server") == 0)
		{	servip_ = (int) atoi (argv[2]);

			if( outfp_ )
				fprintf( outfp_, "Set server IP to <%d>\n", servip_ );

			return (TCL_OK);
		}
		else if (strcasecmp(argv[1], "install-tap") == 0)
		{
			obj = TclObject::lookup(argv[2]);
			if(obj == 0)
			{
				fprintf(stderr, "PASSIVE: 'install-tap' failed (%s) (%s)\n", argv[1], argv[2]);
				return (TCL_ERROR);
			}
	  
			Mac *m = (Mac*) obj;
			m->installTap(this);
			return TCL_OK;
		}
		else if (strcmp (argv[1], "set-logfile") == 0) {
			outfp_ = fopen (argv[2], "w");
			if (outfp_)
				return (TCL_OK);
			else 
				return (TCL_ERROR);
		}
		else if (strcmp (argv[1], "set-grphfile") == 0) {
			hcfp_ = fopen (argv[2], "w");
			if (hcfp_)
				return (TCL_OK);
			else 
				return (TCL_ERROR);
		}
	}
  
	// If the command hasn't been processed by FirewallAgent()::command,
  	// call the command() function for the base class
  	return (Agent::command(argc, argv));
}

void FirewallAgent::recv(Packet* pkt, Handler*)
{
	printPacket( pkt, outfp_ );

	if( !enable_ )
	{	send(pkt, 0);		// re-send packet into the network
		return;
	}
	
	// dispatch packet to different events
	hdr_cmn *th = hdr_cmn::access(pkt);		// common header (size, etc)
	hdr_tcp *tcph = hdr_tcp::access(pkt);		// TCP header
	hdr_ip *iph = hdr_ip::access(pkt);		// IP header
	int saddr = iph->saddr();
	int sport = iph->sport();
	int daddr = iph->daddr();
	int dport = iph->dport();
	int flags = tcph->flags();
	int seqno = tcph->seqno();
	int ackno = tcph->ackno();
	int datalen = th->size() - tcph->hlen(); // # payload bytes
//Debug
//fprintf( outfp_, "packet saddr: %d, servip: %d\n", saddr, servip_ );
	if ( saddr == servip_ )						// packet from server
	{
		if( (flags&TH_SYN) && (flags&TH_ACK) )	// SYN/ACK packet
		{	// process SYN/ACK
			string key = hct_encap( daddr, dport, sport );

			// search for previous SYN/ACK, handle re-tx
			int i;
			for( i = 0; i < HCT_NUM; i++ )
				if( hct[i].find(key) != hct[i].end() )	// found
					break;

			if ( i == HCT_NUM )
				hct[0][key] = seqno + 1;	// record seq# into new HCT entry
		}
		else if( flags & TH_RST ) { 	// server send reset
			// search for connection in htc array
			for( int i =0; i < HCT_NUM; i++ )
			{
				string key = hct_encap( daddr, dport, sport );

				hct_tab::iterator it = hct[i].find( key );
				if ( it != hct[i].end() )
				{	// Half-open connection match found
					hct[i].erase ( key );		// remove from HCT
					update_hc(DOWN);

					if( outfp_ )
						fprintf( outfp_, "Server terminate connection from IP %d, score: %d, class: %s\n", daddr, ipct[daddr].score, class_str(ipct[daddr].ipcls) );

					break;				// no need to look further
				}
			} // end for loop
		}
	}
	// client IP address
	else if ( flags & TH_SYN )
	{
		// process client SYN
		ipct_tab::iterator it = ipct.find(saddr);
		if( it != ipct.end() )				// look for existing IP
		{
			ipct[saddr].update_score(S1);	// found, update score
			update_hc(UP);		// increment half-open count

			if( outfp_ )
				fprintf( outfp_, "SYN recv from old IP %d, score: %d, class: %s\n", 
			saddr, ipct[saddr].score, class_str(ipct[saddr].ipcls) );

		}
		else
		{

			if( outfp_ )
				fprintf( outfp_, "SYN recv from new IP %d \n", saddr );
			ipct[saddr] = ipct_dat();		// add new entry
			update_hc(UP);
		}

		// If IP is bad, sent spoof RST packet
		if ( enable_spf_ && ipct[saddr].ipcls == CLS_BD )
		{
//			send(pkt, 0);
			send_spf( saddr, sport, daddr, dport, 
						(int)(TH_RST|TH_PSH), seqno, ackno );
			update_hc(DOWN);
			return;			// end here	
		}
	}
	else	// Client's ACK packet

	// This is a quick hack for the attack simulation
	// b/c the starting seq# is always 0, so we know exactly
	// what is the ACK and SEQ in the 3rd packet
	// << remove if starting seq changed. >>
	if ( seqno == 1 && ackno == 1 && datalen == 0 )		
	{
		// search packet in htc array
		for( int i =0; i < HCT_NUM; i++ )
		{
			string key = hct_encap( saddr, sport, dport );

			hct_tab::iterator it = hct[i].find( key );
			if ( it != hct[i].end() && seqno == hct[i][key] )
			{	// 3rd ACK match found
				hct[i].erase ( key );		// remove from HCT
				ipct[saddr].update_score(-S1);	// update score for connection completion
				update_hc(DOWN);

				if( outfp_ )
					fprintf( outfp_, "3rd ACK recv from IP %d, score: %d, class: %s\n", 
		saddr, ipct[saddr].score, class_str(ipct[saddr].ipcls) );

				break;				// no need to look further
			}
		} // end for loop
	}

//print_ipct();
	send(pkt, 0);		// re-send packet back into the network
}

void FirewallAgent::tap(const Packet *packet)
{
 
	//process a snooped packet for information
	Packet* pkt = packet->copy();
//	fprintf( stdout, "Sniff>> " );
	printPacket( pkt, outfp_ );
	Packet::free(pkt);
}

void FirewallAgent::printPacket( Packet *pkt, FILE *out )
{
	if ( !out ) return;

	hdr_tcp *tcph = hdr_tcp::access(pkt);	// TCP header
	hdr_cmn *th = hdr_cmn::access(pkt);	// common header (size, etc)
	hdr_ip* iph = hdr_ip::access(pkt);
	int datalen = th->size() - tcph->hlen(); // # payload bytes

	fprintf( out, "%s %2.5f src[%2d:%2d] dst[%2d:%2d] hlen:%2d dlen:%3d seq:%5d ack:%5d flags:0x%02x %s\n",
		(iph->daddr() == servip_)?"->>":"<<-",
		now(),
		iph->saddr(), iph->sport(),
		iph->daddr(), iph->dport(),
		tcph->hlen(),
		datalen,
		tcph->seqno(),
		tcph->ackno(),
		tcph->flags(), 
		flagstr(tcph->flags())
		);
}

const char * FirewallAgent::flagstr(int hflags)
{
	// update this if tcp header flags change
	if (hflags < 0 || (hflags > 63)) {
		return ("<invalid>");
	}
	if (hflags == 0) {	
		return "<null>";
	}

	static char outstr[100];

	strcpy( outstr, "<");

	if( hflags & TH_URG )
		strcat( outstr, "URG," );
	if( hflags & TH_ACK )
		strcat( outstr, "ACK," );
	if( hflags & TH_PSH )
		strcat( outstr, "PSH," );
	if( hflags & TH_RST )
		strcat( outstr, "RST," );
	if( hflags & TH_SYN )
		strcat( outstr, "SYN," );
	if( hflags & TH_FIN )
		strcat( outstr, "FIN," );
	strcat( outstr, ">");
	return outstr;
}

//---- Firewall operation functions ------------------------

void FirewallAgent::timeout()
{
	if ( !enable_spf_ ){	
		update_hc(MARK);
		return;
	}
//Debug
//fprintf( outfp_, "TICK timeout at %2.5f\n", now() );
	// take care of last HCT element, T1 timeout
	hct_tab::iterator ii;
	for( ii = hct[HCT_NUM-1].begin(); ii != hct[HCT_NUM-1].end(); ii++ )
	{
		// send spoof ACK to all entries
		int saddr = hct_decap( ii->first, 1 );

		send_spf( saddr, hct_decap( ii->first, 2 ), servip_,
			  hct_decap( ii->first, 3 ), TH_ACK, ii->second, 1 );

		// update score for this IP addr
		ipct[saddr].update_score( S2 );
		update_hc(DOWN);

		if( outfp_ )
			fprintf( outfp_, "T1 expire from %s, score: %d, class: %s\n", 
		(ii->first).c_str(), ipct[saddr].score, class_str(ipct[saddr].ipcls) );

	}

	// process T2 timeout HCT entries
	for( ii = hct[HCT_T2].begin(); ii != hct[HCT_T2].end(); ii++ )
	{
		int saddr = hct_decap( ii->first, 1 );
		if( ipct[saddr].ipcls != CLS_NT )		// ignore non-Neutral IP
			continue;

		// send spoof ACK to Neutral entries
		send_spf( saddr, hct_decap( ii->first, 2 ), servip_,
			  hct_decap( ii->first, 3 ), TH_ACK, ii->second, 1 );

		hct[HCT_T2].erase(ii);			// remove entry
		update_hc(DOWN);			// update hc count
		ipct[saddr].update_score( S2 );		// update score the IP

		if( outfp_ )
			fprintf( outfp_, "T2 expire from %s, score: %d, class: %s\n", 
		(ii->first).c_str(), ipct[saddr].score, class_str(ipct[saddr].ipcls) );

	}

	hct[HCT_NUM-1].clear();					// clear the last entry
	for( int i = HCT_NUM -1; i > 0; i-- )	// shift all HCT entries 1 position downward
		hct[i].swap( hct[i-1] );

	// score decaying for every entries in IPCT
	ipct_tab::iterator ipi;
	for( ipi = ipct.begin(); ipi != ipct.end(); ipi++ )
		(ipi->second).update_score( -SDCY );
}

void FirewallAgent::send_spf
( 	int saddr, 
	int sport, 
	int daddr,
	int dport, 
	int flags, 
	int seq,
	int ack
)
{
		Packet* pkt = allocpkt();			// create spoof packet
		hdr_tcp *tcph = hdr_tcp::access(pkt);
		hdr_ip* iph = hdr_ip::access(pkt);

		tcph->seqno() = seq;				// add seqno
		tcph->ackno() = ack;				// ack number
		tcph->flags() = flags;				// set flags

		iph->saddr() = saddr;
		iph->sport() = sport;
		iph->daddr() = daddr;
		iph->dport() = dport;

		if( outfp_ )
			fprintf( outfp_, "***** spoof <%s> packet sent ******\n", flagstr(flags) );
		//printPacket( pkt, outfp_);

		send(pkt, 0);		// send out spoof packet
}

string FirewallAgent::hct_encap( int addr, int s_port, int d_port )
{	
	char *buf;
	buf = (char *)malloc(sizeof(char)*100);

	sprintf( buf, "%d-%d-%d", addr, s_port, d_port );
	string ind( buf );

	free(buf);
	return ind;
}

int FirewallAgent::hct_decap( string ind, int opt )
{
	int pos1 = ind.find_first_of("-");
	int pos2 = ind.find_last_of("-");

	if ( opt == 1 )
		return atoi( ind.substr(0, pos1).c_str() );		// extract source addr
	else if ( opt == 2 )
		return atoi( ind.substr(pos1+1,pos2).c_str() );		// extract source port
	else
		return atoi( ind.substr(pos2+1).c_str() );		// extract dest port
}


void FirewallAgent::print_ipct(void)
{
	printf("IPCT\nIP\t\tScore\t\tClass\n");

	ipct_tab::iterator ii;
	for( ii = ipct.begin(); ii != ipct.end(); ii++ )
	{
		printf("%d\t\t%d\t\t%s\n", 
			ii->first, (ii->second).score, class_str((ii->second).ipcls) );
	}
	printf("\n");
}

void FirewallAgent::print_hct(void)
{
	//printf("\nHCT\n");
	hct_tab::iterator ii;
	for( int i = 0; i < HCT_NUM; i++ )
	{	printf("\nHCT #%d\n", i );
		for( ii = hct[i].begin(); ii != hct[i].end(); ii++ )
			printf("%s\t\t%d\n", (ii->first).c_str(), ii->second );
	}
}

void FirewallAgent::update_hc( int dir )
{
	if ( dir != MARK )
		(dir == UP)? hc_count_++ : hc_count_--;

	if( hcfp_ )
		fprintf( hcfp_, "%2.5f\t\t%d\n", now(), hc_count_ );
}

//---- FirewallTimer operation functions ------------------------

void FirewallTimer::expire(Event* =0)
{
	//mgr_->timeout();
	//sched(TICK);
}


void FirewallTimer::handle(Event* e)
{
	mgr_->timeout();
	TimerHandler::handle(e);

	// schedule next timeout
	sched(TICK);
}

//
