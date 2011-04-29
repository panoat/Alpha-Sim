

#Create the core event scheduler
set ns [new Simulator]

#Set up name trace file
set f [open Sim01-1.nam w]
$ns namtrace-all $f

#Create 6 nodes
set atk [$ns node]	;#Attacker node
set cln [$ns node]	;#Client node
set r1 [$ns node]	;#Border router
set r2 [$ns node]	;#internal router
set fw [$ns node]	;#Firewall
set srv [$ns node]	;#Server

#Create links
$ns duplex-link $atk $r1 100mb 5ms DropTail
$ns duplex-link $cln $r1 2mb 5ms DropTail
$ns duplex-link $r2 $srv 100mb 5ms DropTail

#Create LAN
$ns make-lan "$fw $r1 $r2" 100mb 1ms LL Queue/DropTail Mac/802_3

#Show queue length at routers

#Set up queue limit of the routers

$ns rtproto Session

set pgp [new PagePool/Math]
set tmp [new RandomVariable/Constant]
$tmp set val_ 1024
$pgp ranvar-size $tmp

set server [new Http/Server $ns $srv]
$server set-page-generator $pgp

set client1 [new Http/Client $ns $cln]
set tmp [new RandomVariable/Exponential]
$tmp set avg_ 5
$client1 set-interval-generator $tmp
$client1 set-page-generator $pgp

set client2 [new Http/Client $ns $atk]
set tmp2 [new RandomVariable/Exponential]
$tmp2 set avg_ 0
$client2 set-interval-generator $tmp2
$client2 set-page-generator $pgp

#Distinguish flows by different colors
$ns color 1 Blue
$ns color 2 Red
$client1 set class_ 1
$client2 set class_ 2


set startTime 1
set finishTime 50
$ns at $startTime "start-connection"
$ns at $finishTime "finish"


proc start-connection {} {
	global ns server client1 client2 pgp
	$client1 connect $server
	$client2 connect $server
	$client1 send-request $server GET $pgp
	$client2 send-request $server GET $pgp
}

proc finish {} {
	global ns f
	$ns flush-trace
	close $f
#	exec nam Sim01-1.nam &
	exit 0
}

$ns run
