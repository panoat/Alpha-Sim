
## Panoat Chuchaisri
## FW Simulator
##


set opt(namtr)	"Sim01-3.nam"
set opt(tr)	"Sim01-3.out"
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
	exec nam $opt(namtr) &
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
	$ns duplex-link $node(1) $node(2) 100Mb 5ms DropTail
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

#Create flooder agent and attach to ATK node
set f0 [new Agent/Flooder]
#$f0 set rate_ 0.05Mb
#$f0 set random_ 1
$ns attach-agent $node(0) $f0

#Create telnet session for client node
set src [new Agent/TCP]
$ns attach-agent $node(1) $src

#Create TCP sink at server
set sink1 [new Agent/TCPSink]
$ns attach-agent $node(5) $sink1
set sink2 [new Agent/TCPSink]
$ns attach-agent $node(5) $sink2

#connect src to sink
$ns connect $src $sink1
$ns connect $f0 $sink2

set tnet [new Application/FTP]
#$tnet set interval_ 1
$tnet attach-agent $src

#Create TCP sink at server
set sink [new Agent/TCPSink]
$ns attach-agent $node(5) $sink


# Set flows colors
$ns color 1 Blue
$ns color 2 Red
$src set class_ 1
$f0 set class_ 2

$ns at 0.1 "$f0 send-one"
$ns at 0.2 "$tnet start"
$ns at 0.4 "$f0 start"
$ns at 0.75 "$f0 stop"
$ns at 0.8 "$tnet stop"

$ns at $opt(stop) "finish"
$ns run
