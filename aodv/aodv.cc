/*
Copyright (c) 1997, 1998 Carnegie Mellon University.  All Rights
Reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.
3. The name of the author may not be used to endorse or promote products
derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

The AODV code developed by the CMU/MONARCH group was optimized and tuned by Samir Das and Mahesh Marina, University of Cincinnati. The work was partially done in Sun Microsystems. Modified for gratuitous replies by Anant Utgikar, 09/16/02.

 */

//#include <ip.h>

#include <aodv/aodv.h>
#include <aodv/aodv_packet.h>
#include <random.h>
#include <cmu-trace.h>
//#include <time.h>
//#include <energy-model.h>

#define max(a,b)        ( (a) > (b) ? (a) : (b) )
#define CURRENT_TIME    Scheduler::instance().clock()

//#define DEBUG
//#define ERROR

#ifdef DEBUG
static int extra_route_reply = 0;
static int limit_route_request = 0;
static int route_request = 0;
#endif

/* static vars init */
key_pool AODV::global_key_pool;
kchain_pool AODV::global_kchain_pool;
bloom_filter AODV::global_bf;
int key_chain::salt = rand();
int bloom_filter::ds_salt = rand();
int bloom_filter::ds = rand();
list<double> AODV::global_fwd_record;
list<double> AODV::global_rcv_record;
list<double> AODV::global_app_record;
map<int,set<int> > AODV::bc_tree;
int AODV::NEH_num = 0;
int AODV::bct_mode_ = BCT_UNINIT;
int AODV::fwd_mode_ = BCT_PROBE_MODE;

int hdr_aodv::offset_;

/*
  TCL Hooks
 */
static class AODVHeaderClass : public PacketHeaderClass {
public:

    AODVHeaderClass() : PacketHeaderClass("PacketHeader/AODV",
    sizeof (hdr_all_aodv)) {
        bind_offset(&hdr_aodv::offset_);
    }
} class_rtProtoAODV_hdr;

static class AODVclass : public TclClass {
public:

    AODVclass() : TclClass("Agent/AODV") {
    }

    TclObject* create(int argc, const char*const* argv) {
        assert(argc == 5);
        //return (new AODV((nsaddr_t) atoi(argv[4])));
        return (new AODV((nsaddr_t) Address::instance().str2addr(argv[4])));
    }
} class_rtProtoAODV;

int
AODV::command(int argc, const char*const* argv) {
    if (argc == 2) {
        Tcl& tcl = Tcl::instance();

        if (strncasecmp(argv[1], "id", 2) == 0) {
            tcl.resultf("%d", index);
            return TCL_OK;
        }

        if (strcmp(argv[1], "start") == 0) {
            btimer.handle((Event*) 0);

#ifndef AODV_LINK_LAYER_DETECTION
            htimer.handle((Event*) 0);
            ntimer.handle((Event*) 0);
#endif // LINK LAYER DETECTION

            rtimer.handle((Event*) 0);
            return TCL_OK;
        }

        if (strcmp(argv[1], "bct-enable") == 0) {
            bct_mode_ = BCT_ENABLE;
            return TCL_OK;
        }

        if (strcmp(argv[1], "bct-disable") == 0) {
            bct_mode_ = BCT_DISABLE;
            return TCL_OK;
        }

        if (strcmp(argv[1], "stat-summary") == 0) {
            stat_summary();
            return TCL_OK;
        }

        if (strcmp(argv[1], "bct-summary") == 0) {
            bct_summary();
            return TCL_OK;
        }

        if (strcmp(argv[1], "stat-clear") == 0) {
            stat_clear();
            return TCL_OK;
        }

    } else if (argc == 3) {
        if (strcmp(argv[1], "index") == 0) {
            index = atoi(argv[2]);
            return TCL_OK;
        } else if (strcmp(argv[1], "fwd-mode") == 0) {
            fwd_mode_ = atoi(argv[2]);
            return TCL_OK;
        } else if (strcmp(argv[1], "log-target") == 0 || strcmp(argv[1], "tracetarget") == 0) {
            logtarget = (Trace*) TclObject::lookup(argv[2]);
            if (logtarget == 0)
                return TCL_ERROR;
            return TCL_OK;
        } else if (strcmp(argv[1], "drop-target") == 0) {
            int stat = rqueue.command(argc, argv);
            if (stat != TCL_OK) return stat;
            return Agent::command(argc, argv);
        } else if (strcmp(argv[1], "if-queue") == 0) {
            ifqueue = (PriQueue*) TclObject::lookup(argv[2]);

            if (ifqueue == 0)
                return TCL_ERROR;
            return TCL_OK;
        } else if (strcmp(argv[1], "port-dmux") == 0) {
            dmux_ = (PortClassifier *) TclObject::lookup(argv[2]);
            if (dmux_ == 0) {
                fprintf(stderr, "%s: %s lookup of %s failed\n", __FILE__,
                        argv[1], argv[2]);
                return TCL_ERROR;
            }
            return TCL_OK;
        }
    }
    return Agent::command(argc, argv);
}

/*
   Constructor
 */

AODV::AODV(nsaddr_t id) : Agent(PT_AODV),
btimer(this), htimer(this), ntimer(this),
rtimer(this), lrtimer(this), rqueue(){

    index = id;
    seqno = 2;
    bid = 1;

    LIST_INIT(&nbhead);
    LIST_INIT(&bihead);

    logtarget = 0;
    ifqueue = 0;
    last_uid = -1;
    parent_ip = -1;

    bind("key_set_num_",&key_set_num_);
    bind("fake_key_set_num_", &fake_key_set_num_);
    bind("key_set_size_", &key_set_size_);
    bind("local_key_set_size_", &local_key_set_size_);
    bind("kchain_set_num_", &kchain_set_num_);
    bind("fake_kcs_num_", &fake_kcs_num_);
    bind("local_kchain_size_", &local_kchain_size_);
    bind("bf_key_per_set_", &bf_key_per_set_);
    bind("bf_hash_num_", &bf_hash_num_);
    bind("bf_vector_size_", &bf_vector_size_);
    bind("bf_delta_", &bf_delta_);
    bind("bf_delay_", &bf_delay_);
    bind("ecc_delay_", &ecc_delay_);
    bind("fwd_mode_", &fwd_mode_);
    bind("bct_mode_", &bct_mode_);

    if( !(AODV::global_key_pool.is_init()) )    // if key_pool is not init, do it
        AODV::global_key_pool.init_key_pool(key_set_num_, key_set_size_);

    if( !(AODV::global_kchain_pool.is_init()) )
        AODV::global_kchain_pool.init_kchain_pool(kchain_set_num_);

    if( !(AODV::global_bf.is_init()))
        AODV::global_bf.init_bloom_filter(bf_vector_size_, bf_hash_num_);

    local_key_set = global_key_pool.pick_k(local_key_set_size_);

    //---- pick random local key chains -------
    int record[local_kchain_size_-1]; // record picked key chains
    for( int i = 0; i < local_kchain_size_-1; i++ ) // init all to -1
        record[i] = -1;

    int rec_i = 0;
    for( int i = 0; i < local_kchain_size_; ) {
        int rand_i = global_kchain_pool.get_rand_index();
        bool redo = false;
        // search for dup
        for( int j = 0; j <= rec_i; j++ ) {
            if( record[j] == rand_i ) {
                redo = true;
                break;
            }
        }
        if( redo )
            continue;

        key_chain kc;
        kc.init_key_chain(0, global_kchain_pool.get_key(rand_i), rand_i);
        local_key_chain.push_back( kc );
        record[rec_i++] = rand_i;
        i++;
    }

    backup_key_chain.assign(local_key_chain.begin(), local_key_chain.end());    // backup the local key chain
    if( !bc_tree.empty() ) bc_tree.clear();                                     // clear broadcast tree map
    //--- end local key chain initialization ------
}

/*
  Timers
 */

void
BroadcastTimer::handle(Event*) {
    agent->id_purge();
    Scheduler::instance().schedule(this, &intr, BCAST_ID_SAVE);
}

void
HelloTimer::handle(Event*) {
    agent->sendHello();
    double interval = MinHelloInterval +
            ((MaxHelloInterval - MinHelloInterval) * Random::uniform());
    assert(interval >= 0);
    Scheduler::instance().schedule(this, &intr, interval);
}

void
NeighborTimer::handle(Event*) {
    agent->nb_purge();
    Scheduler::instance().schedule(this, &intr, HELLO_INTERVAL);
}

void
RouteCacheTimer::handle(Event*) {
    agent->rt_purge();
#define FREQUENCY 0.5 // sec
    Scheduler::instance().schedule(this, &intr, FREQUENCY);
}

void
LocalRepairTimer::handle(Event* p) { // SRD: 5/4/99
    aodv_rt_entry *rt;
    struct hdr_ip *ih = HDR_IP((Packet *) p);

    /* you get here after the timeout in a local repair attempt */
    /*	fprintf(stderr, "%s\n", __FUNCTION__); */


    rt = agent->rtable.rt_lookup(ih->daddr());

    if (rt && rt->rt_flags != RTF_UP) {
        // route is yet to be repaired
        // I will be conservative and bring down the route
        // and send route errors upstream.
        /* The following assert fails, not sure why */
        /* assert (rt->rt_flags == RTF_IN_REPAIR); */

        //rt->rt_seqno++;
        agent->rt_down(rt);
        // send RERR
#ifdef DEBUG
        fprintf(stderr, "Node %d: Dst - %d, failed local repair\n", index, rt->rt_dst);
#endif
    }
    Packet::free((Packet *) p);
}

/*
   Broadcast ID Management  Functions
 */


void
AODV::id_insert(nsaddr_t id, u_int32_t bid) {
    BroadcastID *b = new BroadcastID(id, bid);

    assert(b);
    b->expire = CURRENT_TIME + BCAST_ID_SAVE;
    LIST_INSERT_HEAD(&bihead, b, link);
}

/* SRD */
bool
AODV::id_lookup(nsaddr_t id, u_int32_t bid) {
    BroadcastID *b = bihead.lh_first;

    // Search the list for a match of source and bid
    for (; b; b = b->link.le_next) {
        if ((b->src == id) && (b->id == bid))
            return true;
    }
    return false;
}

void
AODV::id_purge() {
    BroadcastID *b = bihead.lh_first;
    BroadcastID *bn;
    double now = CURRENT_TIME;

    for (; b; b = bn) {
        bn = b->link.le_next;
        if (b->expire <= now) {
            LIST_REMOVE(b, link);
            delete b;
        }
    }
}

/*
  Helper Functions
 */

double
AODV::PerHopTime(aodv_rt_entry *rt) {
    int num_non_zero = 0, i;
    double total_latency = 0.0;

    if (!rt)
        return ((double) NODE_TRAVERSAL_TIME);

    for (i = 0; i < MAX_HISTORY; i++) {
        if (rt->rt_disc_latency[i] > 0.0) {
            num_non_zero++;
            total_latency += rt->rt_disc_latency[i];
        }
    }
    if (num_non_zero > 0)
        return (total_latency / (double) num_non_zero);
    else
        return ((double) NODE_TRAVERSAL_TIME);

}

/*
  Link Failure Management Functions
 */

static void
aodv_rt_failed_callback(Packet *p, void *arg) {
    ((AODV*) arg)->rt_ll_failed(p);
}

/*
 * This routine is invoked when the link-layer reports a route failed.
 */
void
AODV::rt_ll_failed(Packet *p) {
    struct hdr_cmn *ch = HDR_CMN(p);
    struct hdr_ip *ih = HDR_IP(p);
    aodv_rt_entry *rt;
    nsaddr_t broken_nbr = ch->next_hop_;

#ifndef AODV_LINK_LAYER_DETECTION
    drop(p, DROP_RTR_MAC_CALLBACK);
#else

    /*
     * Non-data packets and Broadcast Packets can be dropped.
     */
    if (!DATA_PACKET(ch->ptype()) ||
            (u_int32_t) ih->daddr() == IP_BROADCAST) {
        drop(p, DROP_RTR_MAC_CALLBACK);
        return;
    }
    log_link_broke(p);
    if ((rt = rtable.rt_lookup(ih->daddr())) == 0) {
        drop(p, DROP_RTR_MAC_CALLBACK);
        return;
    }
    log_link_del(ch->next_hop_);

#ifdef AODV_LOCAL_REPAIR
    /* if the broken link is closer to the dest than source,
       attempt a local repair. Otherwise, bring down the route. */


    if (ch->num_forwards() > rt->rt_hops) {
        local_rt_repair(rt, p); // local repair
        // retrieve all the packets in the ifq using this link,
        // queue the packets for which local repair is done,
        return;
    } else
#endif // LOCAL REPAIR
    {
        drop(p, DROP_RTR_MAC_CALLBACK);
        // Do the same thing for other packets in the interface queue using the
        // broken link -Mahesh
        while ((p = ifqueue->filter(broken_nbr))) {
            drop(p, DROP_RTR_MAC_CALLBACK);
        }
        nb_delete(broken_nbr);
    }

#endif // LINK LAYER DETECTION
}

void
AODV::handle_link_failure(nsaddr_t id) {
    aodv_rt_entry *rt, *rtn;
    Packet *rerr = Packet::alloc();
    struct hdr_aodv_error *re = HDR_AODV_ERROR(rerr);

    re->DestCount = 0;
    for (rt = rtable.head(); rt; rt = rtn) { // for each rt entry
        rtn = rt->rt_link.le_next;
        if ((rt->rt_hops != INFINITY2) && (rt->rt_nexthop == id)) {
            assert(rt->rt_flags == RTF_UP);
            assert((rt->rt_seqno % 2) == 0);
            rt->rt_seqno++;
            re->unreachable_dst[re->DestCount] = rt->rt_dst;
            re->unreachable_dst_seqno[re->DestCount] = rt->rt_seqno;
#ifdef DEBUG
            fprintf(stderr, "%s(%f): %d\t(%d\t%u\t%d)\n", __FUNCTION__, CURRENT_TIME,
                    index, re->unreachable_dst[re->DestCount],
                    re->unreachable_dst_seqno[re->DestCount], rt->rt_nexthop);
#endif // DEBUG
            re->DestCount += 1;
            rt_down(rt);
        }
        // remove the lost neighbor from all the precursor lists
        rt->pc_delete(id);
    }

    if (re->DestCount > 0) {
#ifdef DEBUG
        fprintf(stderr, "%s(%f): %d\tsending RERR...\n", __FUNCTION__, CURRENT_TIME, index);
#endif // DEBUG
        sendError(rerr, false);
    } else {
        Packet::free(rerr);
    }
}

void
AODV::local_rt_repair(aodv_rt_entry *rt, Packet *p) {
#ifdef DEBUG
    fprintf(stderr, "%s: Dst - %d\n", __FUNCTION__, rt->rt_dst);
#endif
    // Buffer the packet
    rqueue.enque(p);

    // mark the route as under repair
    rt->rt_flags = RTF_IN_REPAIR;

    sendRequest(rt->rt_dst);

    // set up a timer interrupt
    Scheduler::instance().schedule(&lrtimer, p->copy(), rt->rt_req_timeout);
}

void
AODV::rt_update(aodv_rt_entry *rt, u_int32_t seqnum, u_int16_t metric,
        nsaddr_t nexthop, double expire_time) {

    rt->rt_seqno = seqnum;
    rt->rt_hops = metric;
    rt->rt_flags = RTF_UP;
    rt->rt_nexthop = nexthop;
    rt->rt_expire = expire_time;
}

void
AODV::rt_down(aodv_rt_entry *rt) {
    /*
     *  Make sure that you don't "down" a route more than once.
     */

    if (rt->rt_flags == RTF_DOWN) {
        return;
    }

    // assert (rt->rt_seqno%2); // is the seqno odd?
    rt->rt_last_hop_count = rt->rt_hops;
    rt->rt_hops = INFINITY2;
    rt->rt_flags = RTF_DOWN;
    rt->rt_nexthop = 0;
    rt->rt_expire = 0;

} /* rt_down function */

/*
  Route Handling Functions
 */

void
AODV::rt_resolve(Packet *p) {
    struct hdr_cmn *ch = HDR_CMN(p);
    struct hdr_ip *ih = HDR_IP(p);
    aodv_rt_entry *rt;

    /*
     *  Set the transmit failure callback.  That
     *  won't change.
     */
    ch->xmit_failure_ = aodv_rt_failed_callback;
    ch->xmit_failure_data_ = (void*) this;
    rt = rtable.rt_lookup(ih->daddr());
    if (rt == 0) {
        rt = rtable.rt_add(ih->daddr());
    }

    /*
     * If the route is up, forward the packet
     */

    if (rt->rt_flags == RTF_UP) {
        assert(rt->rt_hops != INFINITY2);
        forward(rt, p, NO_DELAY);
    }/*
  *  if I am the source of the packet, then do a Route Request.
  */
    else if (ih->saddr() == index) {
        rqueue.enque(p);
        sendRequest(rt->rt_dst);
    }/*
  *	A local repair is in progress. Buffer the packet.
  */
    else if (rt->rt_flags == RTF_IN_REPAIR) {
        rqueue.enque(p);
    }        /*
         * I am trying to forward a packet for someone else to which
         * I don't have a route.
         */
    else {
        Packet *rerr = Packet::alloc();
        struct hdr_aodv_error *re = HDR_AODV_ERROR(rerr);
        /*
         * For now, drop the packet and send error upstream.
         * Now the route errors are broadcast to upstream
         * neighbors - Mahesh 09/11/99
         */

        assert(rt->rt_flags == RTF_DOWN);
        re->DestCount = 0;
        re->unreachable_dst[re->DestCount] = rt->rt_dst;
        re->unreachable_dst_seqno[re->DestCount] = rt->rt_seqno;
        re->DestCount += 1;
#ifdef DEBUG
        fprintf(stderr, "%s: sending RERR...\n", __FUNCTION__);
#endif
        sendError(rerr, false);

        drop(p, DROP_RTR_NO_ROUTE);
    }
}

void
AODV::rt_purge() {
    aodv_rt_entry *rt, *rtn;
    double now = CURRENT_TIME;
    double delay = 0.0;
    Packet *p;

    for (rt = rtable.head(); rt; rt = rtn) { // for each rt entry
        rtn = rt->rt_link.le_next;
        if ((rt->rt_flags == RTF_UP) && (rt->rt_expire < now)) {
            // if a valid route has expired, purge all packets from
            // send buffer and invalidate the route.
            assert(rt->rt_hops != INFINITY2);
            while ((p = rqueue.deque(rt->rt_dst))) {
#ifdef DEBUG
                fprintf(stderr, "%s: calling drop()\n",
                        __FUNCTION__);
#endif // DEBUG
                drop(p, DROP_RTR_NO_ROUTE);
            }
            rt->rt_seqno++;
            assert(rt->rt_seqno % 2);
            rt_down(rt);
        } else if (rt->rt_flags == RTF_UP) {
            // If the route is not expired,
            // and there are packets in the sendbuffer waiting,
            // forward them. This should not be needed, but this extra
            // check does no harm.
            assert(rt->rt_hops != INFINITY2);
            while ((p = rqueue.deque(rt->rt_dst))) {
                forward(rt, p, delay);
                delay += ARP_DELAY;
            }
        } else if (rqueue.find(rt->rt_dst))
            // If the route is down and
            // if there is a packet for this destination waiting in
            // the sendbuffer, then send out route request. sendRequest
            // will check whether it is time to really send out request
            // or not.
            // This may not be crucial to do it here, as each generated
            // packet will do a sendRequest anyway.

            sendRequest(rt->rt_dst);
    }

}

/*
  Packet Reception Routines
 */

void
AODV::recv(Packet *p, Handler*) {
    struct hdr_cmn *ch = HDR_CMN(p);
    struct hdr_ip *ih = HDR_IP(p);
    double delay = 0;

    assert(initialized());
    //assert(p->incoming == 0);
    // XXXXX NOTE: use of incoming flag has been depracated; In order to track direction of pkt flow, direction_ in hdr_cmn is used instead. see packet.h for details.

    if (ch->ptype() == PT_AODV) {
        ih->ttl_ -= 1;
        recvAODV(p);
        return;
    }


    /*
     *  Must be a packet I'm originating...
     */
    if ((ih->saddr() == index) && (ch->num_forwards() == 0)) {
        /*
         * Add the IP Header
         */
        ch->size() += IP_HDR_LEN;
        // Added by Parag Dadhania && John Novatnack to handle broadcasting
        if ((u_int32_t) ih->daddr() != IP_BROADCAST && bct_mode_ != BCT_ENABLE ) {
            ih->ttl_ = NETWORK_DIAMETER;
        }
        // it is a broadcast packet that I'm sending.
        else if( fwd_mode_ == KEYPOOL_MODE || fwd_mode_ == KEYCHAIN_MODE ) {
#ifdef TONY_DBG
printf("%.5f: Node %d creating BFV ....\n",CURRENT_TIME, index );
#endif
            if( fwd_mode_ == KEYCHAIN_MODE && fake_kcs_num_ == 0 )   // only adv key chins w/ all auth keys
                AODV::global_kchain_pool.advance_kchain_pool();

            int max_mark = max_bfv_mark(fwd_mode_);     // maximum allowed BFV "1" mark
            int gen_count = 0;                          // BFV generation counter
            do {
                AODV::global_bf.clear();            // clear old BFV
                AODV::global_bf.change_ds();        // change DS for every new BFV gen

                if( fwd_mode_ == KEYPOOL_MODE ) {
                    key_set key_pick = AODV::global_key_pool.pick_h(bf_key_per_set_, fake_key_set_num_);
                    AODV::global_bf.add_map(key_pick.get_key_list());
                }
                else {     // key-chain mode
                    map<int,int> key_pick = AODV::global_kchain_pool.pick_fake(fake_kcs_num_);
                    AODV::global_bf.add_map(key_pick);
                }
                gen_count++;
            }while( AODV::global_bf.mark_num() > max_mark );     // re-gen bfv until max-mark limit is satisfied

            //--- fill up fake BFV to the max
            delay = NO_DELAY;
#ifdef TONY_DBG
            printf("New BFV (gen%2d)-> ", gen_count);
            AODV::global_bf.print_bfv();
#endif

            int fake_num = (fwd_mode_ == KEYPOOL_MODE)?fake_key_set_num_:fake_kcs_num_;
            if( fake_num > 0 ) {
                AODV::global_bf.fill_bfv(max_mark);
#ifdef TONY_DBG
                printf("New FILLED BFV -> ");
                AODV::global_bf.print_bfv();
#endif
            }
            //--- end Fil BFV -----

        } // ENDIF broadcast packet with key-pool or key-chain mode
        else if( fwd_mode_ == BCT_PROBE_MODE ) {
            AODV::bc_tree.clear();                  // clear bc_tree map on new probing packet
        }

        ih->prio_ = index;    // *hack* record sender ip into unused IPv6 field
    }
  /*
  *  I received a packet that I sent.  Probably
  *  a routing loop.
  */
    else if (ih->saddr() == index) {
        drop(p, DROP_RTR_ROUTE_LOOP);
        return;
    }/*
  *  Packet I'm forwarding...
  */
    else {

        // Tony -- check for legitimate parent node in broadcast tree mode
        // if parent_ip is incorrect, drop the packet
        if( (bct_mode_ == BCT_ENABLE) && (parent_ip != -1) && (parent_ip != ih->prio()) ) {
#ifdef TONY_DBG
            printf("%.5f: Node %d drop INVALID parent node %d packet, valid parent = %d\n", CURRENT_TIME, index, ih->prio(), parent_ip);
#endif
            drop(p, DROP_RTR_ROUTE_LOOP);
            return;
        }

        delay = fwd_delay();
        /*
         *  Check the TTL.  If it is zero, then discard.
         */
        if (--ih->ttl_ == 0) {
            drop(p, DROP_RTR_TTL);
            return;
        }
    }
    // Added by Parag Dadhania && John Novatnack to handle broadcasting
    if ((u_int32_t) ih->daddr() != IP_BROADCAST)
        rt_resolve(p);
    else
        forward((aodv_rt_entry*) 0, p, delay);
}

void
AODV::recvAODV(Packet *p) {
    struct hdr_aodv *ah = HDR_AODV(p);

    assert(HDR_IP(p)->sport() == RT_PORT);
    assert(HDR_IP(p)->dport() == RT_PORT);

    /*
     * Incoming Packets.
     */
    switch (ah->ah_type) {

        case AODVTYPE_RREQ:
            recvRequest(p);
            break;

        case AODVTYPE_RREP:
            recvReply(p);
            break;

        case AODVTYPE_RERR:
            recvError(p);
            break;

        case AODVTYPE_HELLO:
            recvHello(p);
            break;

        default:
            fprintf(stderr, "Invalid AODV type (%x)\n", ah->ah_type);
            exit(1);
    }

}

void
AODV::recvRequest(Packet *p) {
    struct hdr_ip *ih = HDR_IP(p);
    struct hdr_aodv_request *rq = HDR_AODV_REQUEST(p);
    aodv_rt_entry *rt;

    /*
     * Drop if:
     *      - I'm the source
     *      - I recently heard this request.
     */

    if (rq->rq_src == index) {
#ifdef DEBUG
        fprintf(stderr, "%s: got my own REQUEST\n", __FUNCTION__);
#endif // DEBUG
        Packet::free(p);
        return;
    }

    if (id_lookup(rq->rq_src, rq->rq_bcast_id)) {

#ifdef DEBUG
        fprintf(stderr, "%s: discarding request\n", __FUNCTION__);
#endif // DEBUG

        Packet::free(p);
        return;
    }

    /*
     * Cache the broadcast ID
     */
    id_insert(rq->rq_src, rq->rq_bcast_id);



    /*
     * We are either going to forward the REQUEST or generate a
     * REPLY. Before we do anything, we make sure that the REVERSE
     * route is in the route table.
     */
    aodv_rt_entry *rt0; // rt0 is the reverse route

    rt0 = rtable.rt_lookup(rq->rq_src);
    if (rt0 == 0) { /* if not in the route table */
        // create an entry for the reverse route.
        rt0 = rtable.rt_add(rq->rq_src);
    }

    rt0->rt_expire = max(rt0->rt_expire, (CURRENT_TIME + REV_ROUTE_LIFE));

    if ((rq->rq_src_seqno > rt0->rt_seqno) ||
            ((rq->rq_src_seqno == rt0->rt_seqno) &&
            (rq->rq_hop_count < rt0->rt_hops))) {
        // If we have a fresher seq no. or lesser #hops for the
        // same seq no., update the rt entry. Else don't bother.
        rt_update(rt0, rq->rq_src_seqno, rq->rq_hop_count, ih->saddr(),
                max(rt0->rt_expire, (CURRENT_TIME + REV_ROUTE_LIFE)));
        if (rt0->rt_req_timeout > 0.0) {
            // Reset the soft state and
            // Set expiry time to CURRENT_TIME + ACTIVE_ROUTE_TIMEOUT
            // This is because route is used in the forward direction,
            // but only sources get benefited by this change
            rt0->rt_req_cnt = 0;
            rt0->rt_req_timeout = 0.0;
            rt0->rt_req_last_ttl = rq->rq_hop_count;
            rt0->rt_expire = CURRENT_TIME + ACTIVE_ROUTE_TIMEOUT;
        }

        /* Find out whether any buffered packet can benefit from the
         * reverse route.
         * May need some change in the following code - Mahesh 09/11/99
         */
        assert(rt0->rt_flags == RTF_UP);
        Packet *buffered_pkt;
        while ((buffered_pkt = rqueue.deque(rt0->rt_dst))) {
            if (rt0 && (rt0->rt_flags == RTF_UP)) {
                assert(rt0->rt_hops != INFINITY2);
                forward(rt0, buffered_pkt, NO_DELAY);
            }
        }
    }
    // End for putting reverse route in rt table


    /*
     * We have taken care of the reverse route stuff.
     * Now see whether we can send a route reply.
     */

    rt = rtable.rt_lookup(rq->rq_dst);

    // First check if I am the destination ..

    if (rq->rq_dst == index) {

#ifdef DEBUG
        fprintf(stderr, "%d - %s: destination sending reply\n",
                index, __FUNCTION__);
#endif // DEBUG


        // Just to be safe, I use the max. Somebody may have
        // incremented the dst seqno.
        seqno = max(seqno, rq->rq_dst_seqno) + 1;
        if (seqno % 2) seqno++;

        sendReply(rq->rq_src, // IP Destination
                1, // Hop Count
                index, // Dest IP Address
                seqno, // Dest Sequence Num
                MY_ROUTE_TIMEOUT, // Lifetime
                rq->rq_timestamp); // timestamp

        Packet::free(p);
    }        // I am not the destination, but I may have a fresh enough route.

    else if (rt && (rt->rt_hops != INFINITY2) &&
            (rt->rt_seqno >= rq->rq_dst_seqno)) {

        //assert (rt->rt_flags == RTF_UP);
        assert(rq->rq_dst == rt->rt_dst);
        //assert ((rt->rt_seqno%2) == 0);	// is the seqno even?
        sendReply(rq->rq_src,
                rt->rt_hops + 1,
                rq->rq_dst,
                rt->rt_seqno,
                (u_int32_t) (rt->rt_expire - CURRENT_TIME),
                //             rt->rt_expire - CURRENT_TIME,
                rq->rq_timestamp);
        // Insert nexthops to RREQ source and RREQ destination in the
        // precursor lists of destination and source respectively
        rt->pc_insert(rt0->rt_nexthop); // nexthop to RREQ source
        rt0->pc_insert(rt->rt_nexthop); // nexthop to RREQ destination

#ifdef RREQ_GRAT_RREP

        sendReply(rq->rq_dst,
                rq->rq_hop_count,
                rq->rq_src,
                rq->rq_src_seqno,
                (u_int32_t) (rt->rt_expire - CURRENT_TIME),
                //             rt->rt_expire - CURRENT_TIME,
                rq->rq_timestamp);
#endif

        // TODO: send grat RREP to dst if G flag set in RREQ using rq->rq_src_seqno, rq->rq_hop_counT

        // DONE: Included gratuitous replies to be sent as per IETF aodv draft specification. As of now, G flag has not been dynamically used and is always set or reset in aodv-packet.h --- Anant Utgikar, 09/16/02.

        Packet::free(p);
    }/*
  * Can't reply. So forward the  Route Request
  */
    else {
        //printf("Node %d forward route request\n", index);
        ih->saddr() = index;
        ih->daddr() = IP_BROADCAST;
        rq->rq_hop_count += 1;
        // Maximum sequence number seen en route
        if (rt) rq->rq_dst_seqno = max(rt->rt_seqno, rq->rq_dst_seqno);
        forward((aodv_rt_entry*) 0, p, DELAY);
    }

}

void
AODV::recvReply(Packet *p) {
    //struct hdr_cmn *ch = HDR_CMN(p);
    struct hdr_ip *ih = HDR_IP(p);
    struct hdr_aodv_reply *rp = HDR_AODV_REPLY(p);
    aodv_rt_entry *rt;
    char suppress_reply = 0;
    double delay = 0.0;

#ifdef DEBUG
    fprintf(stderr, "%d - %s: received a REPLY\n", index, __FUNCTION__);
#endif // DEBUG


    /*
     *  Got a reply. So reset the "soft state" maintained for
     *  route requests in the request table. We don't really have
     *  have a separate request table. It is just a part of the
     *  routing table itself.
     */
    // Note that rp_dst is the dest of the data packets, not the
    // the dest of the reply, which is the src of the data packets.

    rt = rtable.rt_lookup(rp->rp_dst);

    /*
     *  If I don't have a rt entry to this host... adding
     */
    if (rt == 0) {
        rt = rtable.rt_add(rp->rp_dst);
    }

    /*
     * Add a forward route table entry... here I am following
     * Perkins-Royer AODV paper almost literally - SRD 5/99
     */

    if ((rt->rt_seqno < rp->rp_dst_seqno) || // newer route
            ((rt->rt_seqno == rp->rp_dst_seqno) &&
            (rt->rt_hops > rp->rp_hop_count))) { // shorter or better route

        // Update the rt entry
        rt_update(rt, rp->rp_dst_seqno, rp->rp_hop_count,
                rp->rp_src, CURRENT_TIME + rp->rp_lifetime);

        // reset the soft state
        rt->rt_req_cnt = 0;
        rt->rt_req_timeout = 0.0;
        rt->rt_req_last_ttl = rp->rp_hop_count;

        if (ih->daddr() == index) { // If I am the original source
            // Update the route discovery latency statistics
            // rp->rp_timestamp is the time of request origination

            rt->rt_disc_latency[(unsigned char) rt->hist_indx] = (CURRENT_TIME - rp->rp_timestamp)
                    / (double) rp->rp_hop_count;
            // increment indx for next time
            rt->hist_indx = (rt->hist_indx + 1) % MAX_HISTORY;
        }

        /*
         * Send all packets queued in the sendbuffer destined for
         * this destination.
         * XXX - observe the "second" use of p.
         */
        Packet *buf_pkt;
        while ((buf_pkt = rqueue.deque(rt->rt_dst))) {
            if (rt->rt_hops != INFINITY2) {
                assert(rt->rt_flags == RTF_UP);
                // Delay them a little to help ARP. Otherwise ARP
                // may drop packets. -SRD 5/23/99
                forward(rt, buf_pkt, delay);
                delay += ARP_DELAY;
            }
        }
    } else {
        suppress_reply = 1;
    }

    /*
     * If reply is for me, discard it.
     */

    if (ih->daddr() == index || suppress_reply) {
        Packet::free(p);
    }/*
  * Otherwise, forward the Route Reply.
  */
    else {
        // Find the rt entry
        aodv_rt_entry *rt0 = rtable.rt_lookup(ih->daddr());
        // If the rt is up, forward
        if (rt0 && (rt0->rt_hops != INFINITY2)) {
            assert(rt0->rt_flags == RTF_UP);
            rp->rp_hop_count += 1;
            rp->rp_src = index;
            forward(rt0, p, NO_DELAY);
            // Insert the nexthop towards the RREQ source to
            // the precursor list of the RREQ destination
            rt->pc_insert(rt0->rt_nexthop); // nexthop to RREQ source

        } else {
            // I don't know how to forward .. drop the reply.
#ifdef DEBUG
            fprintf(stderr, "%s: dropping Route Reply\n", __FUNCTION__);
#endif // DEBUG
            drop(p, DROP_RTR_NO_ROUTE);
        }
    }
}

void
AODV::recvError(Packet *p) {
    struct hdr_ip *ih = HDR_IP(p);
    struct hdr_aodv_error *re = HDR_AODV_ERROR(p);
    aodv_rt_entry *rt;
    u_int8_t i;
    Packet *rerr = Packet::alloc();
    struct hdr_aodv_error *nre = HDR_AODV_ERROR(rerr);

    nre->DestCount = 0;

    for (i = 0; i < re->DestCount; i++) {
        // For each unreachable destination
        rt = rtable.rt_lookup(re->unreachable_dst[i]);
        if (rt && (rt->rt_hops != INFINITY2) &&
                (rt->rt_nexthop == ih->saddr()) &&
                (rt->rt_seqno <= re->unreachable_dst_seqno[i])) {
            assert(rt->rt_flags == RTF_UP);
            assert((rt->rt_seqno % 2) == 0); // is the seqno even?
#ifdef DEBUG
            fprintf(stderr, "%s(%f): %d\t(%d\t%u\t%d)\t(%d\t%u\t%d)\n", __FUNCTION__, CURRENT_TIME,
                    index, rt->rt_dst, rt->rt_seqno, rt->rt_nexthop,
                    re->unreachable_dst[i], re->unreachable_dst_seqno[i],
                    ih->saddr());
#endif // DEBUG
            rt->rt_seqno = re->unreachable_dst_seqno[i];
            rt_down(rt);

            // Not sure whether this is the right thing to do
            Packet *pkt;
            while ((pkt = ifqueue->filter(ih->saddr()))) {
                drop(pkt, DROP_RTR_MAC_CALLBACK);
            }

            // if precursor list non-empty add to RERR and delete the precursor list
            if (!rt->pc_empty()) {
                nre->unreachable_dst[nre->DestCount] = rt->rt_dst;
                nre->unreachable_dst_seqno[nre->DestCount] = rt->rt_seqno;
                nre->DestCount += 1;
                rt->pc_delete();
            }
        }
    }

    if (nre->DestCount > 0) {
#ifdef DEBUG
        fprintf(stderr, "%s(%f): %d\t sending RERR...\n", __FUNCTION__, CURRENT_TIME, index);
#endif // DEBUG
        sendError(rerr);
    } else {
        Packet::free(rerr);
    }

    Packet::free(p);
}

/*
   Packet Transmission Routines
 */

void
AODV::forward(aodv_rt_entry *rt, Packet *p, double delay) {
    struct hdr_cmn *ch = HDR_CMN(p);
    struct hdr_ip *ih = HDR_IP(p);

    if (ih->ttl_ == 0) {

#ifdef DEBUG
        fprintf(stderr, "%s: calling drop()\n", __PRETTY_FUNCTION__);
#endif // DEBUG

        drop(p, DROP_RTR_TTL);
        return;
    }
    /*  // Original code
        if (ch->ptype() != PT_AODV && ch->direction() == hdr_cmn::UP &&
                ((u_int32_t) ih->daddr() == IP_BROADCAST)
                || (ih->daddr() == here_.addr_)) {
    printf("Node %d receive broadcast/normal packet from %d\n", index, ih->saddr());
            dmux_->recv(p, 0);
            return;
        }
     */
    if (ih->daddr() == here_.addr_) {
#ifdef TONY_DBG
        printf("%.5f: Node %5d receives normal packet from %d\n", CURRENT_TIME, index, ih->saddr());
#endif
        dmux_->recv(p, 0);
        return;
    }

    bool non_aodv = ch->ptype() != PT_AODV;
    bool receiving = ch->direction() == hdr_cmn::UP;
    bool broadcast_packet = ((u_int32_t) ih->daddr() == IP_BROADCAST);
    //bool packet_for_me = ((u_int32_t) ih->daddr() == index);
    bool use_bct_mode = bct_mode_ == BCT_ENABLE;

    if ( non_aodv && receiving && (broadcast_packet || use_bct_mode ) ) {
        // receiving a non-AODV Broadcast packet or a packet in BCT mode

        if (ch->uid() == last_uid) {    // Duplicate packet received
#ifdef TONY_DBG
            printf("%.5f: Node %5d drop DUP broadcast packet\n", CURRENT_TIME, index);
#endif
            drop(p, DROP_RTR_ROUTE_LOOP);
            return;
        }

        // Node receive NEW broadcast packet
#ifdef TONY_DBG
        printf("%.5f: Node %5d recv NEW msg originate from %d, forward by %d\n", \
                CURRENT_TIME, index, ih->saddr(), ih->prio() );
#endif
        if( fwd_mode_ == BCT_PROBE_MODE && use_bct_mode ) { // broadcast tree records parent_ip
#ifdef TONY_DBG
            printf("[%d] ---parent----> [%d]\n", ih->prio(), index);
#endif
            parent_ip = ih->prio();                         // record parent ip at local node
            AODV::bc_tree[parent_ip].insert(index);      // record child ip into bc_tree map
        }

        ih->prio_ = index;                                  // *hack* record fwding ip into unused IPv6 field
        last_uid = ch->uid();                               // record last broadcast msg
        AODV::global_rcv_record.push_back(CURRENT_TIME);    // record receiving time

        int verf_result = bfv_verification();           // verify BFV
        if ( verf_result == BFV_PASS) {                 // verfication pass, fwd and pass up to app
#ifdef TONY_DBG
            printf("%.5f: Node %5d -> packet from %d -- BFV verification PASS\n", CURRENT_TIME, index, ih->saddr());
#endif
            AODV::global_fwd_record.push_back(CURRENT_TIME + delay);    // record forwarding time
            AODV::global_app_record.push_back(CURRENT_TIME + app_delay());    // record app receving time
            Scheduler::instance().schedule(dmux_, p->copy(), app_delay());    // pass up w/ BF verification delay
        }
        else if ( verf_result == BFV_FAULT_PASS ) {     // faulty BFV pass, fwd only
#ifdef TONY_DBG
            printf("%.5f: Node %5d -> packet from %d -- BFV verification FAULTY PASS\n", CURRENT_TIME, index, ih->saddr());
#endif
            AODV::global_fwd_record.push_back(CURRENT_TIME + delay);    // record forwarding time
        }
        else if ( verf_result == BFV_NOT_ENOUGH_HIT && fake_key_set_num_ == 0 ) {     // not enough BFV hit, act like auth-first
            delay += ecc_delay_;        // fwd w/ increase delay
            AODV::global_fwd_record.push_back(CURRENT_TIME + delay);    // record forwarding time
            AODV::global_app_record.push_back(CURRENT_TIME + app_delay());    // record app receving time
            Scheduler::instance().schedule(dmux_, p->copy(), app_delay());
        }
        else {      // BFV fail
#ifdef TONY_DBG
            printf("%.5f: Node %5d -> packet from %d -- BFV verification FAIL\n", CURRENT_TIME, index, ih->saddr());
#endif
            drop(p, DROP_RTR_ROUTE_LOOP);
            return;
        }
    }

    if( fwd_mode_ == KEYCHAIN_MODE && fake_kcs_num_ == 0 ) {                        // if the packet is authentic
        local_key_chain.assign(backup_key_chain.begin(), backup_key_chain.end());   // key advance is permanent
    }

    if (rt) {
        assert(rt->rt_flags == RTF_UP);
        rt->rt_expire = CURRENT_TIME + ACTIVE_ROUTE_TIMEOUT;
        ch->next_hop_ = rt->rt_nexthop;
        ch->addr_type() = NS_AF_INET;
        ch->direction() = hdr_cmn::DOWN; //important: change the packet's direction
    } else { // if it is a broadcast packet
        // assert(ch->ptype() == PT_AODV); // maybe a diff pkt type like gaf
        assert(ih->daddr() == (nsaddr_t) IP_BROADCAST);
        ch->addr_type() = NS_AF_NONE;
        ch->direction() = hdr_cmn::DOWN; //important: change the packet's direction
    }

    /*------- Schedule packet -------*/
    if ( (broadcast_packet && !use_bct_mode && non_aodv)
            || (fwd_mode_ == BCT_PROBE_MODE) ) {
        // broadcast w/ BFV delay
        printf("%.5f: Node %d broadcast packet ID%d\n", CURRENT_TIME + delay, index, ch->uid());
        Scheduler::instance().schedule(target_, p, delay ); // fwd w/ BF verification delay
    }
    else if ( broadcast_packet && !non_aodv ) {
        assert(rt == 0);
        /*
         *  Jitter the sending of AODV broadcast packets by 10ms
         */
        printf("%.5f: Node %d broadcast AODV packet.\n", CURRENT_TIME, index );
        Scheduler::instance().schedule(target_, p,
                0.01 * Random::uniform());
    }
    else if ( use_bct_mode && non_aodv ) {
        // use unicast to simulate BCT
        set<int> children = AODV::bc_tree[index];
        for( set<int>::iterator it = children.begin(); it != children.end(); it++) {
            Packet *np = p->copy();
            struct hdr_ip *ih = HDR_IP(np);
            ih->daddr() = *it;
            printf("%.5f: Node %d send a normal packet to Node %d\n",CURRENT_TIME + delay, index, *it);
            Scheduler::instance().schedule(target_, np, delay);
            //**************** PROBLEM HERE ******************//
            // packet is not received by the destination
            // probably need to submit it through aodv function...
            // -- todo-- analyze trace file
        }
    }
    else {  // send normal packet
        printf("%.5f: Node %d send normal packet to %d with %.2f delay.\n", CURRENT_TIME, index, ih->daddr(), delay);
        if (delay > 0.0) {
            Scheduler::instance().schedule(target_, p, delay);
        } else {
            // Not a broadcast packet, no delay, send immediately
            Scheduler::instance().schedule(target_, p, 0.);
        }
    }
    /*---- End packet scheduling -----*/
}

int
AODV::bfv_verification() {
    if( fwd_mode_ == FWDFIRST_MODE || fwd_mode_ == BCT_PROBE_MODE )     // Forwarding-first
        return BFV_PASS;

    if( fwd_mode_ == AUTHFIRST_MODE ) {     // Authentication-first
        if( fake_key_set_num_ == 0 )
            return BFV_PASS;
        else
            return BFV_FAIL;
    }

    // Key-pool or Key-chain mode
    int result, fake_num;
    if( fwd_mode_ == KEYPOOL_MODE ) {
        result = AODV::global_bf.check_key_set(local_key_set, required_hit());
        fake_num = fake_key_set_num_;
    }
    else {
        backup_key_chain.assign(local_key_chain.begin(), local_key_chain.end());
        int count = AODV::global_kchain_pool.get_key_index();
        result = AODV::global_bf.check_key_chain(backup_key_chain, count );
        fake_num = fake_kcs_num_;
    }

    if( result == BFV_PASS && fake_num > 0 )        // if BFV pass w/ some fake keys,
            return BFV_FAULT_PASS;                  // return fault pass instead

    if( result == BFV_NOT_ENOUGH_HIT )
        AODV::NEH_num++;

    return result;
}

void
AODV::sendRequest(nsaddr_t dst) {
    // Allocate a RREQ packet
    Packet *p = Packet::alloc();
    struct hdr_cmn *ch = HDR_CMN(p);
    struct hdr_ip *ih = HDR_IP(p);
    struct hdr_aodv_request *rq = HDR_AODV_REQUEST(p);
    aodv_rt_entry *rt = rtable.rt_lookup(dst);

    assert(rt);

    /*
     *  Rate limit sending of Route Requests. We are very conservative
     *  about sending out route requests.
     */

    if (rt->rt_flags == RTF_UP) {
        assert(rt->rt_hops != INFINITY2);
        Packet::free((Packet *) p);
        return;
    }

    if (rt->rt_req_timeout > CURRENT_TIME) {
        Packet::free((Packet *) p);
        return;
    }

    // rt_req_cnt is the no. of times we did network-wide broadcast
    // RREQ_RETRIES is the maximum number we will allow before
    // going to a long timeout.

    if (rt->rt_req_cnt > RREQ_RETRIES) {
        rt->rt_req_timeout = CURRENT_TIME + MAX_RREQ_TIMEOUT;
        rt->rt_req_cnt = 0;
        Packet *buf_pkt;
        while ((buf_pkt = rqueue.deque(rt->rt_dst))) {
            drop(buf_pkt, DROP_RTR_NO_ROUTE);
        }
        Packet::free((Packet *) p);
        return;
    }

#ifdef DEBUG
    fprintf(stderr, "(%2d) - %2d sending Route Request, dst: %d\n",
            ++route_request, index, rt->rt_dst);
#endif // DEBUG

    // Determine the TTL to be used this time.
    // Dynamic TTL evaluation - SRD

    rt->rt_req_last_ttl = max(rt->rt_req_last_ttl, rt->rt_last_hop_count);

    if (0 == rt->rt_req_last_ttl) {
        // first time query broadcast
        ih->ttl_ = TTL_START;
    } else {
        // Expanding ring search.
        if (rt->rt_req_last_ttl < TTL_THRESHOLD)
            ih->ttl_ = rt->rt_req_last_ttl + TTL_INCREMENT;
        else {
            // network-wide broadcast
            ih->ttl_ = NETWORK_DIAMETER;
            rt->rt_req_cnt += 1;
        }
    }

    // remember the TTL used  for the next time
    rt->rt_req_last_ttl = ih->ttl_;

    // PerHopTime is the roundtrip time per hop for route requests.
    // The factor 2.0 is just to be safe .. SRD 5/22/99
    // Also note that we are making timeouts to be larger if we have
    // done network wide broadcast before.

    rt->rt_req_timeout = 2.0 * (double) ih->ttl_ * PerHopTime(rt);
    if (rt->rt_req_cnt > 0)
        rt->rt_req_timeout *= rt->rt_req_cnt;
    rt->rt_req_timeout += CURRENT_TIME;

    // Don't let the timeout to be too large, however .. SRD 6/8/99
    if (rt->rt_req_timeout > CURRENT_TIME + MAX_RREQ_TIMEOUT)
        rt->rt_req_timeout = CURRENT_TIME + MAX_RREQ_TIMEOUT;
    rt->rt_expire = 0;

#ifdef DEBUG
    fprintf(stderr, "(%2d) - %2d sending Route Request, dst: %d, tout %f ms\n",
            ++route_request,
            index, rt->rt_dst,
            rt->rt_req_timeout - CURRENT_TIME);
#endif	// DEBUG


    // Fill out the RREQ packet
    // ch->uid() = 0;
    ch->ptype() = PT_AODV;
    ch->size() = IP_HDR_LEN + rq->size();
    ch->iface() = -2;
    ch->error() = 0;
    ch->addr_type() = NS_AF_NONE;
    ch->prev_hop_ = index; // AODV hack

    ih->saddr() = index;
    ih->daddr() = IP_BROADCAST;
    ih->sport() = RT_PORT;
    ih->dport() = RT_PORT;

    // Fill up some more fields.
    rq->rq_type = AODVTYPE_RREQ;
    rq->rq_hop_count = 1;
    rq->rq_bcast_id = bid++;
    rq->rq_dst = dst;
    rq->rq_dst_seqno = (rt ? rt->rt_seqno : 0);
    rq->rq_src = index;
    seqno += 2;
    assert((seqno % 2) == 0);
    rq->rq_src_seqno = seqno;
    rq->rq_timestamp = CURRENT_TIME;

    Scheduler::instance().schedule(target_, p, 0.);

}

void
AODV::sendReply(nsaddr_t ipdst, u_int32_t hop_count, nsaddr_t rpdst,
        u_int32_t rpseq, u_int32_t lifetime, double timestamp) {
    Packet *p = Packet::alloc();
    struct hdr_cmn *ch = HDR_CMN(p);
    struct hdr_ip *ih = HDR_IP(p);
    struct hdr_aodv_reply *rp = HDR_AODV_REPLY(p);
    aodv_rt_entry *rt = rtable.rt_lookup(ipdst);

#ifdef DEBUG
    fprintf(stderr, "sending Reply from %d at %.2f\n", index, CURRENT_TIME);
#endif // DEBUG
    assert(rt);

    rp->rp_type = AODVTYPE_RREP;
    //rp->rp_flags = 0x00;
    rp->rp_hop_count = hop_count;
    rp->rp_dst = rpdst;
    rp->rp_dst_seqno = rpseq;
    rp->rp_src = index;
    rp->rp_lifetime = lifetime;
    rp->rp_timestamp = timestamp;

    // ch->uid() = 0;
    ch->ptype() = PT_AODV;
    ch->size() = IP_HDR_LEN + rp->size();
    ch->iface() = -2;
    ch->error() = 0;
    ch->addr_type() = NS_AF_INET;
    ch->next_hop_ = rt->rt_nexthop;
    ch->prev_hop_ = index; // AODV hack
    ch->direction() = hdr_cmn::DOWN;

    ih->saddr() = index;
    ih->daddr() = ipdst;
    ih->sport() = RT_PORT;
    ih->dport() = RT_PORT;
    ih->ttl_ = NETWORK_DIAMETER;

    Scheduler::instance().schedule(target_, p, 0.);

}

void
AODV::sendError(Packet *p, bool jitter) {
    struct hdr_cmn *ch = HDR_CMN(p);
    struct hdr_ip *ih = HDR_IP(p);
    struct hdr_aodv_error *re = HDR_AODV_ERROR(p);

#ifdef ERROR
    fprintf(stderr, "sending Error from %d at %.2f\n", index, Scheduler::instance().clock());
#endif // DEBUG

    re->re_type = AODVTYPE_RERR;
    //re->reserved[0] = 0x00; re->reserved[1] = 0x00;
    // DestCount and list of unreachable destinations are already filled

    // ch->uid() = 0;
    ch->ptype() = PT_AODV;
    ch->size() = IP_HDR_LEN + re->size();
    ch->iface() = -2;
    ch->error() = 0;
    ch->addr_type() = NS_AF_NONE;
    ch->next_hop_ = 0;
    ch->prev_hop_ = index; // AODV hack
    ch->direction() = hdr_cmn::DOWN; //important: change the packet's direction

    ih->saddr() = index;
    ih->daddr() = IP_BROADCAST;
    ih->sport() = RT_PORT;
    ih->dport() = RT_PORT;
    ih->ttl_ = 1;

    // Do we need any jitter? Yes
    if (jitter)
        Scheduler::instance().schedule(target_, p, 0.01 * Random::uniform());
    else
        Scheduler::instance().schedule(target_, p, 0.0);

}

/*
   Neighbor Management Functions
 */

void
AODV::sendHello() {
    Packet *p = Packet::alloc();
    struct hdr_cmn *ch = HDR_CMN(p);
    struct hdr_ip *ih = HDR_IP(p);
    struct hdr_aodv_reply *rh = HDR_AODV_REPLY(p);

#ifdef DEBUG
    fprintf(stderr, "sending Hello from %d at %.2f\n", index, Scheduler::instance().clock());
#endif // DEBUG

    rh->rp_type = AODVTYPE_HELLO;
    //rh->rp_flags = 0x00;
    rh->rp_hop_count = 1;
    rh->rp_dst = index;
    rh->rp_dst_seqno = seqno;
    rh->rp_lifetime = (1 + ALLOWED_HELLO_LOSS) * HELLO_INTERVAL;

    // ch->uid() = 0;
    ch->ptype() = PT_AODV;
    ch->size() = IP_HDR_LEN + rh->size();
    ch->iface() = -2;
    ch->error() = 0;
    ch->addr_type() = NS_AF_NONE;
    ch->prev_hop_ = index; // AODV hack

    ih->saddr() = index;
    ih->daddr() = IP_BROADCAST;
    ih->sport() = RT_PORT;
    ih->dport() = RT_PORT;
    ih->ttl_ = 1;

    Scheduler::instance().schedule(target_, p, 0.0);
}

void
AODV::recvHello(Packet *p) {
    //struct hdr_ip *ih = HDR_IP(p);
    struct hdr_aodv_reply *rp = HDR_AODV_REPLY(p);
    AODV_Neighbor *nb;

    nb = nb_lookup(rp->rp_dst);
    if (nb == 0) {
        nb_insert(rp->rp_dst);
    } else {
        nb->nb_expire = CURRENT_TIME +
                (1.5 * ALLOWED_HELLO_LOSS * HELLO_INTERVAL);
    }

    Packet::free(p);
}

void
AODV::nb_insert(nsaddr_t id) {
    AODV_Neighbor *nb = new AODV_Neighbor(id);

    assert(nb);
    nb->nb_expire = CURRENT_TIME +
            (1.5 * ALLOWED_HELLO_LOSS * HELLO_INTERVAL);
    LIST_INSERT_HEAD(&nbhead, nb, nb_link);
    seqno += 2; // set of neighbors changed
    assert((seqno % 2) == 0);
}

AODV_Neighbor*
AODV::nb_lookup(nsaddr_t id) {
    AODV_Neighbor *nb = nbhead.lh_first;

    for (; nb; nb = nb->nb_link.le_next) {
        if (nb->nb_addr == id) break;
    }
    return nb;
}

/*
 * Called when we receive *explicit* notification that a Neighbor
 * is no longer reachable.
 */
void
AODV::nb_delete(nsaddr_t id) {
    AODV_Neighbor *nb = nbhead.lh_first;

    log_link_del(id);
    seqno += 2; // Set of neighbors changed
    assert((seqno % 2) == 0);

    for (; nb; nb = nb->nb_link.le_next) {
        if (nb->nb_addr == id) {
            LIST_REMOVE(nb, nb_link);
            delete nb;
            break;
        }
    }

    handle_link_failure(id);

}

/*
 * Purges all timed-out Neighbor Entries - runs every
 * HELLO_INTERVAL * 1.5 seconds.
 */
void
AODV::nb_purge() {
    AODV_Neighbor *nb = nbhead.lh_first;
    AODV_Neighbor *nbn;
    double now = CURRENT_TIME;

    for (; nb; nb = nbn) {
        nbn = nb->nb_link.le_next;
        if (nb->nb_expire <= now) {
            nb_delete(nb->nb_addr);
        }
    }

}

void
AODV::stat_summary() {
    //printf("\n====================================\n");
    //printf("%.5f: ", CURRENT_TIME);
    stat_of(AODV::global_rcv_record, "receiving");
    stat_of(AODV::global_fwd_record, "forwarding");
    stat_of(AODV::global_app_record, "application");
    printf("%d\n", AODV::NEH_num);
    //printf("====================================\n");
    stat_clear();
}

void
AODV::bct_summary() {
    map<int, set<int> >::iterator it;
    printf("    Broadcast Tree:\n");
    for( it = AODV::bc_tree.begin(); it != AODV::bc_tree.end(); it++ ) {
        printf("    Node %4d : ", it->first);
        set<int>::iterator sit;
        for( sit = (it->second).begin(); sit != (it->second).end(); sit++ )
            printf("%d,", *sit);
        printf("\n");
    }

}

void
AODV::stat_of( list<double> lst, const char* desc ) {
    double sum = 0.0;
    int size = (int)(lst.size());

    //printf("Total %s nodes = %d\n", desc, size );
    printf("%d\t", size);

    list<double>::iterator it;
    double max = -1;
    double min = -1;

    if( lst.size() > 0 ) {
        max = lst.front();
        min = lst.front();
    }

    for( it = lst.begin(); it != lst.end(); it++ ) {
        sum += *it;

        if( *it > max ) max = *it;
        if( *it < min ) min = *it;
    }

    //printf("Average %s time = %f sec\n", desc, (sum / size) );
    printf("%.8f\t%.8f\t%.8f\t", min, size>0?(sum/size):-1, max);
}

void
AODV::stat_clear() {
    AODV::global_rcv_record.clear();
    AODV::global_fwd_record.clear();
    AODV::global_app_record.clear();
    AODV::NEH_num = 0;
}

double
AODV::fwd_delay() {
    switch (fwd_mode_) {
        case AUTHFIRST_MODE :   return ecc_delay_;
        case BCT_PROBE_MODE :
        case FWDFIRST_MODE :    return NO_DELAY;
        case KEYPOOL_MODE:
        case KEYCHAIN_MODE:     return bf_delay_;
    }
    return 0;
}

double
AODV::app_delay() {
    switch (fwd_mode_) {
        case AUTHFIRST_MODE :
        case BCT_PROBE_MODE :
        case FWDFIRST_MODE :    return ecc_delay_;
        case KEYPOOL_MODE :
        case KEYCHAIN_MODE:     return ecc_delay_ + bf_delay_ ;
    }
    return 0;
}