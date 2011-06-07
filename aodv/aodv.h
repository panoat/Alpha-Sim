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

The AODV code developed by the CMU/MONARCH group was optimized and tuned by Samir Das and Mahesh Marina, University of Cincinnati. The work was partially done in Sun Microsystems.

 */

#ifndef __aodv_h__
#define __aodv_h__

//#include <agent.h>
//#include <packet.h>
//#include <sys/types.h>
//#include <cmu/list.h>
//#include <scheduler.h>

#include <list>
#include <map>
#include <vector>
#include <time.h>
#include <cmu-trace.h>
#include <priqueue.h>
#include <aodv/aodv_rtable.h>
#include <aodv/aodv_rqueue.h>
#include <classifier/classifier-port.h>

/*
  Allows local repair of routes 
 */
#define AODV_LOCAL_REPAIR

/*
  Allows AODV to use link-layer (802.11) feedback in determining when
  links are up/down.
 */
#define AODV_LINK_LAYER_DETECTION

/*
  Causes AODV to apply a "smoothing" function to the link layer feedback
  that is generated by 802.11.  In essence, it requires that RT_MAX_ERROR
  errors occurs within a window of RT_MAX_ERROR_TIME before the link
  is considered bad.
 */
#define AODV_USE_LL_METRIC

/*
  Only applies if AODV_USE_LL_METRIC is defined.
  Causes AODV to apply omniscient knowledge to the feedback received
  from 802.11.  This may be flawed, because it does not account for
  congestion.
 */
//#define AODV_USE_GOD_FEEDBACK


class AODV;

#define MY_ROUTE_TIMEOUT        10                      	// 100 seconds
#define ACTIVE_ROUTE_TIMEOUT    10				// 50 seconds
#define REV_ROUTE_LIFE          6				// 5  seconds
#define BCAST_ID_SAVE           6				// 3 seconds


// No. of times to do network-wide search before timing out for 
// MAX_RREQ_TIMEOUT sec. 
#define RREQ_RETRIES            3  
// timeout after doing network-wide search RREQ_RETRIES times
#define MAX_RREQ_TIMEOUT	10.0 //sec

/* Various constants used for the expanding ring search */
#define TTL_START     5
#define TTL_THRESHOLD 7
#define TTL_INCREMENT 2 

// This should be somewhat related to arp timeout
#define NODE_TRAVERSAL_TIME     0.03             // 30 ms
#define LOCAL_REPAIR_WAIT_TIME  0.15 //sec

// Should be set by the user using best guess (conservative) 
#define NETWORK_DIAMETER        30             // 30 hops

// Must be larger than the time difference between a node propagates a route 
// request and gets the route reply back.

//#define RREP_WAIT_TIME     (3 * NODE_TRAVERSAL_TIME * NETWORK_DIAMETER) // ms
//#define RREP_WAIT_TIME     (2 * REV_ROUTE_LIFE)  // seconds
#define RREP_WAIT_TIME         1.0  // sec

#define ID_NOT_FOUND    0x00
#define ID_FOUND        0x01
//#define INFINITY        0xff

// The followings are used for the forward() function. Controls pacing.
#define DELAY 1.0           // random delay
#define NO_DELAY 0.0       // no delay

// think it should be 30 ms
#define ARP_DELAY 0.01      // fixed delay to keep arp happy


#define HELLO_INTERVAL          1               // 1000 ms
#define ALLOWED_HELLO_LOSS      3               // packets
#define BAD_LINK_LIFETIME       3               // 3000 ms
#define MaxHelloInterval        (1.25 * HELLO_INTERVAL)
#define MinHelloInterval        (0.75 * HELLO_INTERVAL)

// Tony

// forwarding mode
#define AUTHFIRST_MODE          0x00
#define FWDFIRST_MODE           0x01
#define KEYPOOL_MODE            0x02
#define KEYCHAIN_MODE           0x03
#define BCT_PROBE_MODE          0x04

// return value of BFV verification
#define BFV_NOT_ENOUGH_HIT      0x0A
#define BFV_PASS                0x0B
#define BFV_FAIL                0x0C
#define BFV_FAULT_PASS          0x0D

// Broadcast tree mode
#define BCT_ENABLE              1
#define BCT_DISABLE             0
#define BCT_UNINIT              -1

#define TONY_DBG

/*
  Timers (Broadcast ID, Hello, Neighbor Cache, Route Cache)
 */
class BroadcastTimer : public Handler {
public:

    BroadcastTimer(AODV* a) : agent(a) {
    }
    void handle(Event*);
private:
    AODV *agent;
    Event intr;
};

class HelloTimer : public Handler {
public:

    HelloTimer(AODV* a) : agent(a) {
    }
    void handle(Event*);
private:
    AODV *agent;
    Event intr;
};

class NeighborTimer : public Handler {
public:

    NeighborTimer(AODV* a) : agent(a) {
    }
    void handle(Event*);
private:
    AODV *agent;
    Event intr;
};

class RouteCacheTimer : public Handler {
public:

    RouteCacheTimer(AODV* a) : agent(a) {
    }
    void handle(Event*);
private:
    AODV *agent;
    Event intr;
};

class LocalRepairTimer : public Handler {
public:

    LocalRepairTimer(AODV* a) : agent(a) {
    }
    void handle(Event*);
private:
    AODV *agent;
    Event intr;
};

/*
  Broadcast ID Cache
 */
class BroadcastID {
    friend class AODV;
public:

    BroadcastID(nsaddr_t i, u_int32_t b) {
        src = i;
        id = b;
    }
protected:
    LIST_ENTRY(BroadcastID) link;
    nsaddr_t src;
    u_int32_t id;
    double expire; // now + BCAST_ID_SAVE s
};

LIST_HEAD(aodv_bcache, BroadcastID);

//--------- Tony's Extension --------------

class key_set {
public:

    key_set() {

    } // empty key list

    key_set(int i, int size) {
        gen_key_set(i, size);
    }

    key_set subset(int k, bool fake) {

#ifdef TONY_DBG
        printf("KS pick subset of %d keys .... %s\n", k, (fake?"FAKE ":""));
#endif
        key_set out;

        int i = 0;
        while (i < k) {
            int rand_i = (rand() % key_list.size()) + lowest_i;
            map<int,int> out_list = out.get_key_list();
            if (out_list.find(rand_i) != out_list.end()) // dup
                continue;

            out.add(rand_i, fake?rand():key_list[rand_i] );
            i++;
        }

//        printf("finished\n");
        return out;
    }

    map<int, int> get_key_list() {
        return key_list;
    }

    void add(int index, int key) {
        key_list[index] = key;
    }

    void merge(map<int,int> list) {
        key_list.insert(list.begin(), list.end());
    }

    void print() {
        map<int,int>::iterator it;
        for (it = key_list.begin(); it != key_list.end(); it++) {
            printf("%3d -- %10X\n", it->first, it->second);
        }
    }

protected:
    map<int, int> key_list;
    int lowest_i;

    void gen_key_set(int i, int size) {
#ifdef TONY_DBG
    printf("KS generate key set %d .... \n", i);
#endif
        //srand(time(0));
        lowest_i = i;
        key_list.clear();
        for (int j = i; j < i + size; j++) {
            key_list[j] = rand();
        }

//        printf("finished\n");
    }
};

class key_pool {
public:

    key_pool(){ srand(time(0)); };

    void init_key_pool(int s_num, int s_size) {
        set_num = s_num;
        set_size = s_size;

        gen_key_pool();
    }

    bool is_init() {
        return !(key_set_list.empty());
    }

    key_set pick_k(int k) { // pick k keys from a random set
        int set_id = rand() % set_num; // pick random set
#ifdef TONY_DBG
        printf("Pick %d keys from set %d\n", k, set_id);
#endif
        return key_set_list[set_id].subset(k,false);
    }

    key_set pick_h(int h, int fake_num) { // pick h keys from every set with some fake key set
#ifdef TONY_DBG
        printf("KP pick %d keys from every set with %d fake set.... \n", h, fake_num);
#endif
        key_set out;

        //-- randomly pick fake key set
        bool fake_set[set_num];
        for( int i = 0; i < set_num; i++ )      // init all to false
            fake_set[i] = false;

        int fake_count = 0;
        while( fake_count < fake_num ) {
            int i = rand() % set_num;
            if( fake_set[i] == false ) {
                fake_set[i] = true;
                fake_count++;
            }
        }

        for (int i = 0; i < set_num; i++) { // loop for every set
            key_set pick = key_set_list[i].subset(h, fake_set[i]);
#ifdef TONY_DBG
            pick.print();
#endif
            out.merge(pick.get_key_list()); // merge the set into out
        }
//        printf("KP pick_h finished\n");

        return out;
    }

    void print() {
        map<int, key_set>::iterator it;
        for (it = key_set_list.begin(); it != key_set_list.end(); it++)
            (it->second).print();
    }

protected: // imply N pool size = n*m
    int set_num; // number of sets (n)
    int set_size; // set's size (m)

    map<int, key_set> key_set_list;

    void gen_key_pool() {
#ifdef TONY_DBG
        printf("KP generate key pool ....\n");
#endif
        for (int i = 0; i < set_num; i++) {
            key_set tmp(i*set_size, set_size);
            key_set_list[i] = tmp;
        }
//        printf("KP generation finished\n");
#ifdef TONY_DBG
        print();
#endif
    }
};

class key_chain {
public:
    key_chain(){};

    void init_key_chain( int ind, int key, int pos ) {
        key_index = ind;
        current_key = key;
        kc_position = pos;
    }

    void advance_key() {
#ifdef TONY_DBG
printf("[%08X]--->[", current_key);
#endif
        key_index++;
        srand(current_key ^ salt);
        current_key = rand();
#ifdef TONY_DBG
printf("%08X]\n", current_key);
#endif
    }

    int get_key() {
        return current_key;
    }

    int get_index() {
        return key_index;
    }

    int get_keypos() {
        return kc_position;
    }

protected:
    int key_index;          // current key index in the chain
    int current_key;        // the key itself
    int kc_position;        // key position in the KC pool
    static int salt;

    void print() {
        printf("-- KC[%d] --- %010X\n", key_index, current_key);
    }
};

class kchain_pool {
public:
    kchain_pool(){};

    void init_kchain_pool(int s_num) {
        set_num = s_num;
        key_index = 0;
        gen_kchain_pool();
#ifdef TONY_DBG
        print();
#endif
    }

    int get_key(int ind) {
        list<key_chain>::iterator it = key_list.begin();
        advance(it, ind);
        return it->get_key();
    }

    int get_rand_index() {
        return rand() % set_num;
    }

    int get_key_index() {
        return key_index;
    }

    bool is_init() {
        return !key_list.empty();
    }

    void advance_kchain_pool() {
        key_index++;
        list<key_chain>::iterator it;
        for( it = key_list.begin(); it != key_list.end(); it++ ) {
            it->advance_key();
        }
    }

    map<int,int> pick_fake(int fake_num ) {

        list<int> fake_ind;         // list to record fake index
        if( fake_num > 0 ) {
            for( int i = 0; i < set_num; i++)
                fake_ind.push_back(i);          // fill the list w/ all indices

            while( (int)(fake_ind.size()) > fake_num ) {  // while
                list<int>::iterator it = fake_ind.begin();
                advance( it, rand() % fake_ind.size() );
                fake_ind.erase(it);        // randomly remove index
            }
        }

        map<int,int> out;
#ifdef TONY_DBG
        printf("Fake keys at position: ");
        list<int>::iterator f_it;
        for( f_it = fake_ind.begin(); f_it != fake_ind.end(); f_it++ )
            printf("%d,", *f_it );
        printf("\n");
#endif
        for(int i = 0; i < set_num; i++ ) {
            int data;
            if( !fake_ind.empty() && i == fake_ind.front() ) {  // if fake index
                data = rand();                                  // use random data
                fake_ind.pop_front();                           // remove from list
            }                                                   // else,
            else data = get_key(i);                             // use authentic key

            out[i] = data;                                      // add to output
        }

        return out;
    }

    void print() {
        list<key_chain>::iterator it;
        int i = 0;
        printf("Keychain Pool\n");
        for( it = key_list.begin(); it != key_list.end(); it++ )
            printf("[%03d] %010X\n", i++, it->get_key());
        printf("\n");
    }
    
protected:
    int set_num;
    int key_index;
    list<key_chain> key_list;
    
    void gen_kchain_pool() {
        key_list.clear();
        for(int i = 0; i < set_num; i++) {
            key_chain tmp;
            tmp.init_key_chain(0, rand(), i);
            key_list.push_back(tmp);
        }
    }
};

class bloom_filter {
public:

    bool is_init() {
        return !(bf_vector.empty());
    }

    void init_bloom_filter(int bfv_size, int hash_size) {
//        current_index = 0;
        // set hash's random number
        for (int i = 0; i < hash_size ; i++)
            hash_list.push_back(rand());

        // init bfv
        for( int i = 0; i < bfv_size ; i++ )
            bf_vector.push_back(false);
    }

    void add_map( map<int,int> in ) {
        map<int,int>::iterator it;
        for ( it=in.begin() ; it != in.end(); it++ ) {
            add(it->first, it->second);
        }
    }

    void add(int index, int key) {

        key_index[index] = index; // record index
#ifdef TONY_DBG
printf("BF add key index %d\n", index);
#endif
        for ( unsigned int i = 0; i < hash_list.size(); i++) { // insert into BFV
            bf_vector[bf_index( bloom_filter::ds ^ key, hash_list[i])] = true;
        }
    }

    int check_key_chain(list<key_chain> chain, int current_index ) {
        list<key_chain>::iterator it;

        for( it = chain.begin(); it != chain.end(); it++ ) {
#ifdef TONY_DBG
            printf("checking key %4d ---- %08X\n", it->get_keypos(), it->get_key());
#endif
            int it_index = it->get_index();

            if( it_index > current_index )          // index is old
                return BFV_FAIL;

            while( it_index < current_index )       // advance the key until equal to current index
                it->advance_key();

            if( !check_data(it->get_key()) )        // check for BFV
                return BFV_FAIL;
        }
        return BFV_PASS;
    }

    int check_key_set(key_set set, int required_hit) {
        int index_hit = 0;
        map<int, int>::iterator it;
        map<int, int> keys = set.get_key_list();
        for (it = keys.begin(); it != keys.end(); it++) {
            if (check_index(it->first)) { // index hit
                index_hit++;
#ifdef TONY_DBG
                printf("BF key check for index %d\n", it->first);
#endif
                if (!check_data(it->second)) // fail BFV
                    return BFV_FAIL;
            }
        }

        if (index_hit < required_hit)
            return BFV_NOT_ENOUGH_HIT;

        return BFV_PASS;
    }

    void clear() {
        // clear bf_vector
        for (unsigned int i = 0; i < bf_vector.size(); i++)
            bf_vector[i] = false;

        key_index.clear(); // clear key index set
    }

    void print_bfv() {
        for( unsigned int i = 0; i < bf_vector.size(); i++ )
            printf("%d", (bf_vector[i]?1:0) );
        printf("\n");
    }

    // return list containing indices of all "0" bits in BFV
    list<int> unmark_bits() {
        list<int> unmark;   // list of un-mark bits' index

        // record number of existing "0"
        for(unsigned int i = 0; i < bf_vector.size(); i++ ) {
            if( !(bf_vector[i]) )
                unmark.push_back(i);
        }

        return unmark;
    }

    int unmark_num() {          // number of "0" bits in the BFV
        return unmark_bits().size();
    }

    int mark_num() {            // number of "1" bits in the BFV
        return bf_vector.size() - unmark_num();
    }
    
    void fill_bfv(unsigned int fill_size) {       // fill BFV to the maximum possible marks

        list<int> unmark = unmark_bits();
#ifdef TONY_DBG
        printf("The number of \"1\" bits in BFV (%d) -> (%d)\n", bf_vector.size() - unmark.size(), fill_size );
#endif
        // randomly select index from the list and mark
        while( unmark.size() > 0 && (bf_vector.size() - unmark.size() < fill_size) ) {
            list<int>::iterator it = unmark.begin();
            int rand_i = rand() % unmark.size();
            advance(it, rand_i);                    // move 'it' into position
            bf_vector[*it] = true;
            unmark.erase(it);
        }
    }

    void change_ds() {
        srand( bloom_filter::ds_salt ^ bloom_filter::ds );
        bloom_filter::ds = rand();
    }
    
protected:

    std::vector<int> hash_list;     // hash list for 'add'
    std::vector<bool> bf_vector;    // store 'bit' of BFV
    map<int, int> key_index;        // store key index
//    int current_index;              // current key index (for key-chain mode)

    static int ds_salt;             // for simulating DS changes
    static int ds;                  // current DS

    // finding which bit in BFV to be set to "1" for 'data'
    int bf_index(int data, int hash) {

        int bfvs = bf_vector.size();
#ifdef TONY_DBG
printf("%08X xor %08X = %08X(%d) , mod %d = %d\n", data, hash, (data ^ hash), (data ^ hash), bfvs, (data ^ hash) % bfvs);
#endif
        return (data ^ hash) % bfvs;
    }

    bool check_index(int index) {
        if (key_index.find(index) == key_index.end())
            return false;
        return true;
    }

    bool check_data(int data) {
        for (unsigned int i = 0; i < hash_list.size(); i++) {
            if (bf_vector[bf_index(bloom_filter::ds ^ data, hash_list[i])] == false)
                return false;
        }

        return true;
    }
};
//---------- End Tony's -------------------

/*
  The Routing Agent
 */
class AODV : public Agent {
    /*
     * make some friends first
     */

    friend class aodv_rt_entry;
    friend class BroadcastTimer;
    friend class HelloTimer;
    friend class NeighborTimer;
    friend class RouteCacheTimer;
    friend class LocalRepairTimer;

public:
    AODV(nsaddr_t id);

    void recv(Packet *p, Handler *);

protected:
    int command(int, const char *const *);

    int initialized() {
        return 1 && target_;
    }

    /*
     * Route Table Management
     */
    void rt_resolve(Packet *p);
    void rt_update(aodv_rt_entry *rt, u_int32_t seqnum,
            u_int16_t metric, nsaddr_t nexthop,
            double expire_time);
    void rt_down(aodv_rt_entry *rt);
    void local_rt_repair(aodv_rt_entry *rt, Packet *p);
public:
    void rt_ll_failed(Packet *p);
    void handle_link_failure(nsaddr_t id);
protected:
    void rt_purge(void);

    void enque(aodv_rt_entry *rt, Packet *p);
    Packet* deque(aodv_rt_entry *rt);

    /*
     * Neighbor Management
     */
    void nb_insert(nsaddr_t id);
    AODV_Neighbor* nb_lookup(nsaddr_t id);
    void nb_delete(nsaddr_t id);
    void nb_purge(void);

    /*
     * Broadcast ID Management
     */

    void id_insert(nsaddr_t id, u_int32_t bid);
    bool id_lookup(nsaddr_t id, u_int32_t bid);
    void id_purge(void);

    /*
     * Packet TX Routines
     */
    void forward(aodv_rt_entry *rt, Packet *p, double delay);
    void sendHello(void);
    void sendRequest(nsaddr_t dst);

    void sendReply(nsaddr_t ipdst, u_int32_t hop_count,
            nsaddr_t rpdst, u_int32_t rpseq,
            u_int32_t lifetime, double timestamp);
    void sendError(Packet *p, bool jitter = true);

    /*
     * Packet RX Routines
     */
    void recvAODV(Packet *p);
    void recvHello(Packet *p);
    void recvRequest(Packet *p);
    void recvReply(Packet *p);
    void recvError(Packet *p);

    /*
     * History management
     */

    double PerHopTime(aodv_rt_entry *rt);


    nsaddr_t index; // IP Address of this node
    u_int32_t seqno; // Sequence Number
    int bid; // Broadcast ID

    aodv_rtable rthead; // routing table
    aodv_ncache nbhead; // Neighbor Cache
    aodv_bcache bihead; // Broadcast ID Cache

    /*
     * Timers
     */
    BroadcastTimer btimer;
    HelloTimer htimer;
    NeighborTimer ntimer;
    RouteCacheTimer rtimer;
    LocalRepairTimer lrtimer;

    /*
     * Routing Table
     */
    aodv_rtable rtable;
    /*
     *  A "drop-front" queue used by the routing layer to buffer
     *  packets to which it does not have a route.
     */
    aodv_rqueue rqueue;

    /*
     * A mechanism for logging the contents of the routing
     * table.
     */
    Trace *logtarget;

    /*
     * A pointer to the network interface queue that sits
     * between the "classifier" and the "link layer".
     */
    PriQueue *ifqueue;

    /*
     * Logging stuff
     */
    void log_link_del(nsaddr_t dst);
    void log_link_broke(Packet *p);
    void log_link_kept(nsaddr_t dst);

    /* for passing packets up to agents */
    PortClassifier *dmux_;

    // Tony
    int last_uid;                           // last broadcast packet's uid
    int parent_ip;                          // parent node's ip for broadcast tree
    static map<int, list<int> > bc_tree;     // map that store all children node for each node id

    static key_pool global_key_pool;        // every node share the key pool
    static kchain_pool global_kchain_pool;  // every node share key chain pool
    static bloom_filter global_bf;          // BF to be passed to all nodes

    static list<double> global_fwd_record;  // msg fowarding time record
    static list<double> global_rcv_record;  // msg receiving time record
    static list<double> global_app_record;  // application level receiving time record
    static int NEH_num;               // counting how many nodes verify DS

    key_set local_key_set;                  // for KP
    list<key_chain> local_key_chain;        // for KC
    list<key_chain> backup_key_chain;         // use for roll-back in case of DS verification fail

    // TCL variable
    int key_set_num_;           // number of sets in key pool (n)
    int fake_key_set_num_;      // number of fake key set (must be <n)
    int key_set_size_;          // number of keys in a set (m)
    int local_key_set_size_;    // number of keys stored locally (k)

    int kchain_set_num_;        // number of set in key chain pool (for key-chain mode)
    int fake_kcs_num_;          // number of fake set in kc pool (for key-chain mode)
    int local_kchain_size_;     // number of local key chains (for key-chain mode)

    int bf_key_per_set_;        // number of key/set to be add to BF (h)
    int bf_hash_num_;           // number of hashes for BF
    int bf_vector_size_;        // BFV size (bit) (r)
    int bf_delta_;              // BFV max bit reducer (<=r)

    double bf_delay_;           // BF verification delay (sec)
    double ecc_delay_;          // ECC sig verification delay (sec)

    static int fwd_mode_;              // forwarding mode (Free, Key-pool or Key-chain)
    static int bct_mode_;              // broadcast tree mode flag

    int max_bfv_mark( int mode ) {
        int out;
        if( mode == KEYPOOL_MODE )
            out = (bf_key_per_set_ * key_set_num_ * bf_hash_num_);
        else
            out = (kchain_set_num_ * bf_hash_num_);
#ifdef TONY_DBG
printf("Max bit limit = %d, Delta = %d\n", out, bf_delta_);
#endif
        if( out > bf_vector_size_ ) out = bf_vector_size_;
        out -= bf_delta_;
        if( out < 1 )   return 1;
        return out;
    }
    int required_hit() {
        if( bf_key_per_set_ > key_set_size_ - local_key_set_size_ )
            return bf_key_per_set_ + local_key_set_size_ - key_set_size_;
        else
            return 1;
    }

    void stat_summary();
    void stat_clear();
    void stat_of(list<double> lst, const char* desc);
    
    double fwd_delay();
    double app_delay();
    int bfv_verification();
};

#endif /* __aodv_h__ */
