
## Panoat Chuchaisri
## FW Simulator
##


set opt(namtr)	"Sim01-2.nam"
set opt(tr)	"Sim01-2.out"
set opt(stop)	3
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

set opt(app)	FTP


proc finish {} {
	global ns opt trfd

	$ns flush-trace
	close $trfd
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
			-macType $opt(mac) -chanType $opt(chan)]

	#Create links
	$ns duplex-link $node(0) $node(2) 100Mb 5ms DropTail
	$ns duplex-link $node(1) $node(2) 2Mb 5ms DropTail
	$ns duplex-link $node(3) $node(5) 100Mb 5ms DropTail

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

$ns color 1 Blue
$ns color 2 Red
set tcp0 [$ns create-connection $opt(tcp) $node(1) $opt(sink) $node(5) 1]
set tcp1 [$ns create-connection $opt(tcp) $node(0) $opt(sink) $node(5) 2]

set ftp0 [$tcp0 attach-app $opt(app)]
set ftp1 [$tcp1 attach-app $opt(app)]

$ns at 0.2 "$ftp0 start"
$ns at 0.4 "$ftp1 start"

$ns at $opt(stop) "finish"
$ns run
