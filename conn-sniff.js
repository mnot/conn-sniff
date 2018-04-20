#!/usr/bin/env node

var sprintf = require('sprintf-js').sprintf
var Cap = require('cap').Cap
var decoders = require('cap').decoders
var PROTOCOL = decoders.PROTOCOL

var c = new Cap()
var device = 'en0'
var filter = 'tcp and port 443'
var bufSize = 10 * 1024 * 1024
var buffer = Buffer.alloc(65535)

var linkType = c.open(device, filter, bufSize, buffer)

c.setMinBytes && c.setMinBytes(0)

var openConns = {}
var ttlConns = {}
var byteCounts = {}

function log (type, dstaddr, connId) {
  data = {
    'type': type,
    'dst': dstaddr,
    'open': openConns[dstaddr].size,
    'ttl': ttlConns[dstaddr]
  }
  var output = sprintf("%(type)5s %(dst)15s open: %(open)3i ttl: %(ttl)3i", data)
  if (connId) {
    data['in'] = byteCounts[connId][0]
    data['out'] = byteCounts[connId][1] 
    output += sprintf(" out bytes: %(out)7i in bytes: %(in)7i", data)
  }
  console.log(output)    
}

c.on('packet', function (nbytes, trunc) {
  if (linkType === 'ETHERNET') {
    var ret = decoders.Ethernet(buffer)
    if (ret.info.type === PROTOCOL.ETHERNET.IPV4) {
      ret = decoders.IPV4(buffer, ret.offset)
      var srcaddr = ret.info.srcaddr
      var dstaddr = ret.info.dstaddr
      if (!openConns[dstaddr]) {
        openConns[dstaddr] = new Set()
        ttlConns[dstaddr] = 0
      }
      if (ret.info.protocol === PROTOCOL.IP.TCP) {
        var datalen = ret.info.totallen - ret.hdrlen
        ret = decoders.TCP(buffer, ret.offset)
        datalen -= ret.hdrlen
        if (ret.info.dstport === 443) {  // outbound
          var srcport = ret.info.srcport
          var connId = srcport + ' ' + dstaddr
          if (!byteCounts[connId]) {
            byteCounts[connId] = [0,0]
          }
          byteCounts[connId][1] += datalen
          
          var isFin = ret.info.flags & 0x1
          var isSyn = ret.info.flags & 0x2
          var isRst = ret.info.flags & 0x4
          if (isSyn) {
            openConns[dstaddr].add(srcport)
            ttlConns[dstaddr] += 1
            log('START', dstaddr)
          }
          if (!openConns[dstaddr].has(srcport)) {
            // we're not tracking this
            return
          }
          if (isFin) {
            openConns[dstaddr].delete(srcport)
            log('FIN', dstaddr, connId)
            byteCounts[connId] = [0,0]
          }
          if (isRst) {
            openConns[dstaddr].delete(srcport)
            log('FIN', dstaddr, connId)
            byteCounts[connId] = [0,0]
          }                    
        } else { // inbound
          var connId = ret.info.dstport + ' ' + srcaddr
          if (!byteCounts[connId]) {
            byteCounts[connId] = [0,0]
          }
          byteCounts[connId][0] += datalen

        }
      }
    }
  }
})
