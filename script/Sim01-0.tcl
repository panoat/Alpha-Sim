

#Create the core event scheduler
set ns [new Simulator]

#Set up name trace file
set f [open Sim01.nam w]
$ns namtrace-all $f

#Create 6 nodes
set atk [$ns node]	#Attacker node
set cln [$ns node]	#Client node
set r1 [$ns node]	#Border router
set r2 [$ns node]	#internal router
set fw [$ns node]	#Firewall
set srv [$ns node]	#Server

#Create links
$ns duplex-link $atk $r1 100mb 5ms DropTail
$ns duplex-link $cln $r1 2mb 5ms DropTail
$ns duplex-link $r2 $srv 100mb 5ms DropTail
$ns make-lan "$fw $r1 $r2" 100mb LL Queue/DropTail MAC/CSMA/CD

#Show queue length at routers

#Set up queue limit of the routers


#Create a TCP Source and attach to atk and cln
set atksrc [new Agent/TCP]
set clnsrc [new Agent/TCP]
$ns attach-agent $atk $atksrc
$ns attach-agent $cln $clnsrc

#Create TCP Sink and attach it to Server
set srvdst [new Agent/TCPSink]
$ns attach-agent $srv $srvdst

#Establish TCP connections
$ns connect $atksrc $srvdst
$ns connect $clnsrc $srvdst

#Distinguish flows by different colors
$ns color 1 Blue
$ns color 2 Red
$atksrc set class_ 2
$clnsrc set class_ 1


