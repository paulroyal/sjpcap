package edu.gatech.sjpcap;

import java.io.*;
import java.net.*;

public class PcapParser{
    
	public boolean ipversion4=true;
	////same for both ipv4 and ipv6
    public static final long pcapMagicNumber = 0xA1B2C3D4;
    public static final int globalHeaderSize = 24; 
    public static final int ipProtoTCP = 6;
    public static final int ipProtoUDP = 17;
    
    ////ipv4 specific offset/constants
    public static final int etherHeaderLength = 14;
    public static final int etherTypeOffset = 12;
    public static final int etherTypeIP = 0x800;
    public static final int verIHLOffset = 14; 
    public static final int ipProtoOffset = 23;
    public static final int ipSrcOffset = 26;
    public static final int ipDstOffset = 30;
    
    public static final int udpHeaderLength = 8;
    
    private FileInputStream fis;
     
    private long convertInt(byte[] data){
	return ((data[3] & 0xFF) << 24) | ((data[2] & 0xFF) << 16) | 
	    ((data[1] & 0xFF) << 8) | (data[0] & 0xFF);
    }
    
    private long convertInt(byte[] data, int offset){
	byte[] target = new byte[4];
	System.arraycopy(data, offset, target, 0, target.length);
	return this.convertInt(target);
    }

    private int convertShort(byte[] data){
	return ((data[0] & 0xFF) << 8) | (data[1] & 0xFF);
    }
    
    private int convertShort(byte[] data, int offset){
	byte[] target = new byte[2];
	System.arraycopy(data, offset, target, 0, target.length);
	return this.convertShort(target);
    }
    
    private int readBytes(byte[] data){
	int offset = 0;
	int read = -1;
	while(offset != data.length){
	    try{
		read = this.fis.read(data, offset, data.length - offset);
	    }catch(Exception e){
		break;
	    }
	    if(read == -1)
		break;
	    
	    offset = offset + read;
	}
	if(read != data.length)
	    return -1;
	else
	    return 0;
    }

    private int readGlobalHeader(){
	byte[] globalHeader = new byte[PcapParser.globalHeaderSize];
	
	if(this.readBytes(globalHeader) == -1)
	    return -1;
	if(this.convertInt(globalHeader) != PcapParser.pcapMagicNumber)
	    return -2;
	
	return 0;
    }
    
    public int openFile(String path){
	try{
	    this.fis = new FileInputStream(new File(path));
	}catch(Exception e){
	    e.printStackTrace();
	    return -1;
	}
	
	if(this.readGlobalHeader() < 0)
	    return -1;
	else
	    return 0;
    }

    private boolean isIPPacket(byte[] packet){
	int etherType = this.convertShort(packet, etherTypeOffset);
	if(etherType == PcapParser.etherTypeIP)		
		return true;
	etherType = this.convertShort(packet, PcapParserv6.etherTypeOffset);
	if(etherType==PcapParserv6.etherTypeIP){
		ipversion4=false;
		return true;
		}
	return false;
    }
    
    private boolean isIPversion4(byte[] packet){
    int etherType = this.convertShort(packet, etherTypeOffset);
    return etherType == PcapParser.etherTypeIP;
    }
        
    private boolean isUDPPacket(byte[] packet){
	if(!isIPPacket(packet))
	    return false;
	if(ipversion4)
		return packet[ipProtoOffset] == ipProtoUDP;
	return packet[PcapParserv6.ipProtoOffset]==ipProtoUDP;
    }
    
    private boolean isTCPPacket(byte[] packet){
	if(!isIPPacket(packet))
		return false;
	if(ipversion4)
		return packet[ipProtoOffset] == ipProtoTCP;
	return packet[PcapParserv6.ipProtoOffset]==ipProtoTCP;
    }

    private int getIPHeaderLength(byte[] packet){
    return (packet[verIHLOffset] & 0xF) * 4;
    }
    private int getIPHeaderLengthv6(byte[] packet){
    return 40; ///40 bytes fixed length header for ipv6
    }
    
    private int getTCPHeaderLength(byte[] packet){
	final int inTCPHeaderDataOffset = 12;
	
	int dataOffset = PcapParser.etherHeaderLength +
	    this.getIPHeaderLength(packet) + inTCPHeaderDataOffset;
	return ((packet[dataOffset] >> 4) & 0xF) * 4;
    }
    
    private int getTCPHeaderLengthv6(byte[] packet){
    final int inTCPHeaderDataOffset = 12;
    	
    int dataOffset = PcapParserv6.etherHeaderLength +
    	this.getIPHeaderLengthv6(packet) + inTCPHeaderDataOffset;
    return ((packet[dataOffset] >> 4) & 0xF) * 4;
    }
    
    private IPPacket buildIPPacket(byte[] packet, long timestamp){
	IPPacket ipPacket = new IPPacket(timestamp);
	
	byte[] srcIP = new byte[4];
	System.arraycopy(packet, PcapParser.ipSrcOffset, 
			 srcIP, 0, srcIP.length);
	try{
	    ipPacket.src_ip = InetAddress.getByAddress(srcIP);
	}catch(Exception e){
	    return null;
	}
	
	byte[] dstIP = new byte[4];
	System.arraycopy(packet, PcapParser.ipDstOffset,
			 dstIP, 0, dstIP.length);
	try{
	    ipPacket.dst_ip = InetAddress.getByAddress(dstIP);
	}catch(Exception e){
	    return null;
	}
	
	return ipPacket;
    }
    
    private IPPacket buildIPPacketv6(byte[] packet, long timestamp){
	IPPacket ipPacket = new IPPacket(timestamp);
	
	byte[] srcIP = new byte[16];
	System.arraycopy(packet, PcapParserv6.ipSrcOffset,
			srcIP, 0, srcIP.length);
	try{
		ipPacket.src_ip = InetAddress.getByAddress(srcIP);
	}catch(Exception e){
		return null;
	}
		
	byte[] dstIP = new byte[16];
	System.arraycopy(packet, PcapParserv6.ipDstOffset,
			dstIP, 0, dstIP.length);
	try{
		ipPacket.dst_ip = InetAddress.getByAddress(dstIP);
	}catch(Exception e){
		return null;
	}
	return ipPacket;
    }
    
    private UDPPacket buildUDPPacket(byte[] packet, long timestamp){
	final int inUDPHeaderSrcPortOffset = 0;
	final int inUDPHeaderDstPortOffset = 2;
	
	UDPPacket udpPacket = 
	    new UDPPacket(this.buildIPPacket(packet, timestamp));
	
	int srcPortOffset = PcapParser.etherHeaderLength +
	    this.getIPHeaderLength(packet) + inUDPHeaderSrcPortOffset;
	udpPacket.src_port = this.convertShort(packet, srcPortOffset);
	
	int dstPortOffset = PcapParser.etherHeaderLength +
	    this.getIPHeaderLength(packet) + inUDPHeaderDstPortOffset;
	udpPacket.dst_port = this.convertShort(packet, dstPortOffset);
	
	int payloadDataStart =  PcapParser.etherHeaderLength +
	    this.getIPHeaderLength(packet) + PcapParser.udpHeaderLength;
	byte[] data = new byte[0];
	if((packet.length - payloadDataStart) > 0){
	    data = new byte[packet.length - payloadDataStart];
	    System.arraycopy(packet, payloadDataStart, data, 0, data.length);
	}
	udpPacket.data = data;
	
	return udpPacket;
    }
    
    private UDPPacket buildUDPPacketv6(byte[] packet, long timestamp){
	final int inUDPHeaderSrcPortOffset = 0;
	final int inUDPHeaderDstPortOffset = 2;
	
	UDPPacket udpPacket = 
	    new UDPPacket(this.buildIPPacket(packet, timestamp));
	
	int srcPortOffset = PcapParserv6.etherHeaderLength +
	    this.getIPHeaderLengthv6(packet) + inUDPHeaderSrcPortOffset;
	udpPacket.src_port = this.convertShort(packet, srcPortOffset);
	
	int dstPortOffset = PcapParserv6.etherHeaderLength +
	    this.getIPHeaderLengthv6(packet) + inUDPHeaderDstPortOffset;
	udpPacket.dst_port = this.convertShort(packet, dstPortOffset);
	
	int payloadDataStart =  PcapParserv6.etherHeaderLength +
	    this.getIPHeaderLengthv6(packet) + PcapParser.udpHeaderLength;
	byte[] data = new byte[0];
	if((packet.length - payloadDataStart) > 0){
	    data = new byte[packet.length - payloadDataStart];
   	    System.arraycopy(packet, payloadDataStart, data, 0, data.length);
	}
	udpPacket.data = data;
	
	return udpPacket;
    }
    
    private TCPPacket buildTCPPacket(byte[] packet, long timestamp){
	final int inTCPHeaderSrcPortOffset = 0;
	final int inTCPHeaderDstPortOffset = 2;
	
	TCPPacket tcpPacket = 
	    new TCPPacket(this.buildIPPacket(packet, timestamp));
	
	int srcPortOffset = PcapParser.etherHeaderLength +
	    this.getIPHeaderLength(packet) + inTCPHeaderSrcPortOffset;
	tcpPacket.src_port = this.convertShort(packet, srcPortOffset);
	
	int dstPortOffset = PcapParser.etherHeaderLength +
	    this.getIPHeaderLength(packet) + inTCPHeaderDstPortOffset;
	tcpPacket.dst_port = this.convertShort(packet, dstPortOffset);
	
	int payloadDataStart =  PcapParser.etherHeaderLength +
	    this.getIPHeaderLength(packet) + this.getTCPHeaderLength(packet);
	byte[] data = new byte[0];
	if((packet.length - payloadDataStart) > 0){
	    data = new byte[packet.length - payloadDataStart];
	    System.arraycopy(packet, payloadDataStart, data, 0, data.length);
	}
	tcpPacket.data = data;
	
	return tcpPacket;
    }
    private TCPPacket buildTCPPacketv6(byte[] packet, long timestamp){
    final int inTCPHeaderSrcPortOffset = 0;
    final int inTCPHeaderDstPortOffset = 2;
    	
    TCPPacket tcpPacket = new TCPPacket(this.buildIPPacketv6(packet, timestamp));  
    	
    int srcPortOffset = PcapParserv6.etherHeaderLength +
    	this.getIPHeaderLengthv6(packet) + inTCPHeaderSrcPortOffset;
    tcpPacket.src_port = this.convertShort(packet, srcPortOffset);
    	
    int dstPortOffset = PcapParserv6.etherHeaderLength +
    	this.getIPHeaderLengthv6(packet) + inTCPHeaderDstPortOffset;
    tcpPacket.dst_port = this.convertShort(packet, dstPortOffset);
    	
    int payloadDataStart =  PcapParserv6.etherHeaderLength +
    	this.getIPHeaderLengthv6(packet) + this.getTCPHeaderLengthv6(packet);
    byte[] data = new byte[0];
    if((packet.length - payloadDataStart) > 0){
    	data = new byte[packet.length - payloadDataStart];
    	System.arraycopy(packet, payloadDataStart, data, 0, data.length);
    }
    tcpPacket.data = data;
    	
    return tcpPacket;
    }
    
    private class PcapPacketHeader{

	public static final int pcapPacketHeaderSize = 16;
	public static final int capLenOffset = 8;
    
	public long timestamp;
	public long packetSize;
    
    }
    
    private PcapPacketHeader buildPcapPacketHeader(){
	final int inPcapPacketHeaderSecOffset = 0;
	final int inPcapPacketHeaderUSecOffset = 4;
	
	byte[] header = new byte[PcapPacketHeader.pcapPacketHeaderSize];
        if(this.readBytes(header) < 0)
            return null;
	
	PcapPacketHeader pcapPacketHeader = new PcapPacketHeader();
	pcapPacketHeader.timestamp = 
	    (this.convertInt(header, inPcapPacketHeaderSecOffset) * 1000) +
            (this.convertInt(header, inPcapPacketHeaderUSecOffset) / 1000);
	
	pcapPacketHeader.packetSize = 
	    this.convertInt(header, PcapPacketHeader.capLenOffset);
	
	return pcapPacketHeader;
    }
    
    private Packet buildPacket(byte[] packet, long timestamp){
	if(this.isUDPPacket(packet))
            return this.buildUDPPacket(packet, timestamp);
        else if(this.isTCPPacket(packet))
            return this.buildTCPPacket(packet, timestamp);
        else if(this.isIPPacket(packet))
            return this.buildIPPacket(packet, timestamp);
        else
            return new Packet();
    }
    
    private Packet buildPacketv6(byte[] packet, long timestamp){
	if(this.isUDPPacket(packet))
            return this.buildUDPPacketv6(packet, timestamp);
        else if(this.isTCPPacket(packet))
            return this.buildTCPPacketv6(packet, timestamp);
        else if(this.isIPPacket(packet))
            return this.buildIPPacketv6(packet, timestamp); ///change
        else
            return new Packet();
    }

    public Packet getPacket(){
	final int udpMinPacketSize = 42;
	final int tcpMinPacketSize = 54;
	
	PcapPacketHeader pcapPacketHeader = this.buildPcapPacketHeader();
	if(pcapPacketHeader == null)
	    return Packet.EOF;
	
	byte[] packet = new byte[(int)pcapPacketHeader.packetSize];
	if(this.readBytes(packet) < 0)
	    return Packet.EOF;
	if((this.isUDPPacket(packet) && (packet.length < udpMinPacketSize)) ||
	   (this.isTCPPacket(packet) && (packet.length < tcpMinPacketSize)))
	    return new Packet();
	
	if(isIPversion4(packet))
		return this.buildPacket(packet, pcapPacketHeader.timestamp);
	
	return this.buildPacketv6(packet, pcapPacketHeader.timestamp);
    }
    
    public void closeFile(){
	try{
	    fis.close();
	}catch(Exception e){
	    // do nothing
	}
    }
}
