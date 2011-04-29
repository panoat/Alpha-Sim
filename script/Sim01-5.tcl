
## Panoat Chuchaisri
## FW Simulator
##
## add http traffic between client & server


set opt(namtr)	"Sim01-5.nam"
set opt(fwtr)	"Sim01-5fw.out"
set opt(tr)	"Sim01-5.out"
set opt(httptr) "Sim01-5http.out"
set opt(stop)	6000
set opt(node)	6

set opt(qsize)	100
set opt(bw)	100Mb
set opt(delay)	1ms
set opt(ll)	LL
set opt(ifq)	Queue/DropTail
set opt(mac)	Mac/802_3
set opt(chan)	Channel
set opt(tcp)	TCP
set opt(sink)	TCPSink

#set opt(app)	FTP
set CLIENT  0
set SERVER  1

proc finish {} {
	global ns opt trfd

	$ns flush-trace
	close $trfd
##	exec nam $opt(namtr) &
	exit 0
}

proc create-topology {} {
	global ns opt
	global lan node

	set num $opt(node)
	for {set i 0} {$i < $num} {incr i} {
		set node($i) [$ns node]
	}

	#Create 6 nodes
	$node(0) label "ATK"	;#Attacker node
	$node(1) label "CLN"	;#Client node
	$node(2) label "R1"	;#Border router
	$node(3) label "R2"	;#internal router
	$node(4) label "FW"	;#Firewall
	$node(5) label "SRV"	;#Server

	#Append nodes to LAN
	lappend nodelist $node(2)
	lappend nodelist $node(3)
	lappend nodelist $node(4)

	set lan [$ns newLan $nodelist $opt(bw) $opt(delay) \
			-llType $opt(ll) -ifqType $opt(ifq) \
			-macType $opt(mac) -chanType $opt(chan) \
			-phyType Phy/WiredPhy ]

	#Create links
	$ns duplex-link $node(0) $node(2) 10Mb 5ms DropTail	;# ATK - R1
	$ns duplex-link $node(1) $node(2) 10Mb 5ms DropTail	;# CLN - R1
	$ns duplex-link $node(3) $node(5) 10Mb 5ms DropTail	;# R2 - SRV

	$ns duplex-link-op $node(5) $node(3) queuePos 0.5
	$ns duplex-link-op $node(0) $node(2) queuePos 0.5
	$ns duplex-link-op $node(1) $node(2) queuePos 0.5

	#$ns queue-limit $node(5) $node(3) 10
	#$ns queue-limit $node(0) $node(2) 10
	#$ns queue-limit $node(1) $node(2) 10

}

proc create-trace {} {
	global ns opt

	set trfd [open $opt(tr) w]
	$ns trace-all $trfd
	if {$opt(namtr) != ""} {
		$ns namtrace-all [open $opt(namtr) w]
	}
	return $trfd
}

## MAIN ##

set ns [new Simulator]
set trfd [create-trace]

create-topology

# Setup Packmime (Web Traffic generator)
set rate 100
set pm [new PackMimeHTTP]
$pm set-client $node(1)
$pm set-server $node(5)
$pm set-rate $rate
$pm set-http-1.1

# Setup Packmime random variables
global defaultRNG

# Create RNGs
set flowRNG [new RNG]
set reqsizeRNG [new RNG]
set rspsizeRNG [new RNG]

# Create Random Variables
set flow_arrive [new RandomVariable/PackMimeHTTPFlowArrive $rate]
set req_size [new RandomVariable/PackMimeHTTPFileSize $rate $CLIENT]
set rsp_size [new RandomVariable/PackMimeHTTPFileSize $rate $SERVER]

# Assign RNGs to Random Variables
$flow_arrive use-rng $flowRNG
$req_size use-rng $reqsizeRNG
$rsp_size use-rng $rspsizeRNG

# Set Packmime variables
$pm set-flow_arrive $flow_arrive
$pm set-req_size $req_size
$pm set-rsp_size $rsp_size
$pm set-outfile $opt(httptr)	;# Http trace

#Create firewall agent and attach to FW node
set fw [new Agent/Firewall]
$fw install-tap [[$lan set lanIface_($node(4))] set mac_]
$fw set-outfile $opt(fwtr)
$ns attach-agent $node(4) $fw

#Create flooder agent and attach to ATK node
set f0 [new Agent/Flooder]
$f0 set rate_ 300
$f0 set random_ 0
$f0 set-spoof-ip 2
$ns attach-agent $node(0) $f0

########Test##########
#set f1 [new Agent/Flooder]
#$f1 set rate_ 300
#$f1 set random_ 0
#$f1 set-spoof-ip 2
#$ns attach-agent $node(1) $f1
########Test##########

#Create TCP sink at server
set sink2 [new Agent/TCP/FullTcp]
$ns attach-agent $node(5) $sink2

#connect src to sink
$ns connect $f0 $sink2
$sink2 listen
#$ns connect $f1 $sink2

# Set flows colors
#$ns color 1000 Blue
$ns color 2000 Red
$f0 set class_ 2000
#$pm set class_ 1000

$ns at 0.1 "$f0 send-one"
#$ns at 0.2 "$pm start"
#$ns at 0.4 "$f0 start"
#$ns at 0.5 "$f0 stop"
#$ns at 0.6 "$pm stop"

$ns at $opt(stop) "finish"
$ns run
