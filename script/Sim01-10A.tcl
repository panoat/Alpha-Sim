
## Panoat Chuchaisri
## FW Simulator
##


set priVer	01		;# Primary version #
set secVer	10A		;# Secondary version #

set logDir	"/home/gato/ns-log"
set opt(namtr)	"$logDir/Sim$priVer-$secVer.nam"	;# nam trace file
set opt(fwtr)	"$logDir/Sim$priVer-$secVer-fw.out"	;# firewall trace file
set opt(fwgrph)	"$logDir/Sim$priVer-$secVer-fwgrph.out"	;# firewall trace file
set opt(tr)	"$logDir/Sim$priVer-$secVer.out"	;# ns trace file
set opt(httptr) "$logDir/Sim$priVer-$secVer-http.out"	;# packmime http trace file
set opt(node)	3					;# number of nodes

set opt(pmstr)	0.2				;# start packmime traffic
set opt(pmstp)	30.0				;# stop packmime traffic
set opt(stop)	600.0				;# total simulation runtime (sec)

set opt(tcp)	TCP
set opt(sink)	TCPSink

#set CLN		0
set FW		0
set SRV		1
set ATK		2

proc finish {} {
	global ns opt trfd

##	$ns flush-trace
##	close $trfd
##	exec nam $opt(namtr) &
	exit 0
}

proc create-topology {} {
	global ns opt fw
	global node CLN FW SRV ATK

	#Create & label nodes
#	set node($CLN) [$ns node]
	set node($FW) [$ns node]
	set node($SRV) [$ns node]
	set node($ATK) [$ns node]
#	$node($CLN) label "CLN"		;#Client node
	$node($FW) label "FW"		;#Firewall
	$node($SRV) label "SRV"		;#Server
	$node($ATK) label "ATK"		;#Attacker


#Create FW & Reconnect node's entry point to FW agent (Sniffing)
set fw [new Agent/Firewall]
$fw set-logfile $opt(fwtr)
$fw set-grphfile $opt(fwgrph)
$fw set-server $SRV
#puts "Node entry: [$node($FW) entry] fw entry: [$fw target]"
$ns attach-agent $node($FW) $fw
$node($FW) insert-entry [new RtModule] $fw "target"
#puts "Node entry: [$node($FW) entry] fw entry: [$fw target]"


	#Create links
#	$ns duplex-link $node($CLN) $node($FW) 10Mb 5ms DropTail	;# CLN - FW
	$ns duplex-link $node($ATK) $node($FW) 10Mb 5ms DropTail	;# ATK - FW
	$ns duplex-link $node($FW) $node($SRV) 10Mb 5ms DropTail	;# FW - SRV

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
#set trfd [create-trace]

create-topology

#Create flooder agent and attach to ATK node
set f0 [new Agent/Flooder]
$f0 set rate_ 0.05Mb
$f0 set-ackdelay 190
#$f0 set random_ 1
$ns attach-agent $node($ATK) $f0

#Create TCP sink at server

#-- Testing FullTcp behavior
#set sink0 [new Agent/TCP/FullTcp]
#$sink0 set debug_ 1

#-- Testing Flooder Agent server mode
set sink0 [new Agent/Flooder]

$ns attach-agent $node($SRV) $sink0
$ns connect $f0 $sink0

#$sink0 listen

#puts "client entry: [$node($CLN) entry]"
#puts "client node: $node($CLN)"
#puts ""
#puts "flooder srv: $sink0 "
#puts "flooder srv entry: [$node($SRV) entry]"
#puts "flooder srv node: $node($SRV)"
#puts ""
#puts "flooder atk: $f0"
#puts "flooder atk entry: [$node($ATK) entry]"
#puts "flooder atk node: $node($ATK)"


# Enable Firewall
$fw enable

#Start Simulator
#$ns at 0.1 "$f0 start-atk"
$ns at 0.1 "$sink0 start-srv"
$ns at 10.0 "$f0 send-one"
#$ns at 50.0 "$f0 send-one"
#$ns at 22.0 "$f0 stop"

$ns at $opt(stop) "finish"
$ns run
