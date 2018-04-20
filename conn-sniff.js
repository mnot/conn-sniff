#!/usr/bin/env node

const dns = require('dns')
const lsof = require('lsof')
const sprintf = require('sprintf-js').sprintf
const Cap = require('cap').Cap
const decoders = require('cap').decoders
const PROTOCOL = decoders.PROTOCOL

var c = new Cap()
var device = 'en0'
var filter = 'tcp and port 443'
var bufSize = 10 * 1024 * 1024
var buffer = Buffer.alloc(65535)

var linkType = c.open(device, filter, bufSize, buffer)

c.setMinBytes && c.setMinBytes(0)

var defaultHandler = {
  get: function (target, name) {
    return target.hasOwnProperty(name) ? target[name] : name
  }
}

var openConns = {}
var openPorts = {}
var ttlConns = {}
var byteCounts = {}
var hostNames = new Proxy({}, defaultHandler)

function log (type, dstaddr, connId) {
  setTimeout(function () {
    var data = {
      'type': type,
      'dst': hostNames[dstaddr],
      'open': openConns[dstaddr].size,
      'ttl': ttlConns[dstaddr]
    }
    var output = sprintf('%(type)5s %(dst)60s open: %(open)3i ttl: %(ttl)3i', data)
    if (connId) {
      data['in'] = byteCounts[connId][0]
      data['out'] = byteCounts[connId][1]
      output += sprintf(' out bytes: %(out)7i in bytes: %(in)7i', data)
    }
    console.log(output)
  }, 100)
}

function getProcess (srcPort) {
  lsof.rawTcpPort(srcPort, function (data) {
    if (data.length > 0) {
      openPorts[srcPort] = data[0]['command']
    }
  })
}

function getDns (ip) {
  dns.reverse(ip, function (err, hostnames) {
    if (err) {
      return
    }
    if (hostnames.length > 0) {
      hostNames[ip] = hostnames[0]
    }
  })
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
        var connId
        if (ret.info.dstport === 443) { // outbound
          var srcport = ret.info.srcport
          connId = srcport + ' ' + dstaddr
          if (!byteCounts[connId]) {
            byteCounts[connId] = [0, 0]
          }
          byteCounts[connId][1] += datalen

          var isFin = ret.info.flags & 0x1
          var isSyn = ret.info.flags & 0x2
          var isRst = ret.info.flags & 0x4
          if (isSyn) {
            openConns[dstaddr].add(srcport)
            getProcess(srcport)
            getDns(dstaddr)
            ttlConns[dstaddr] += 1
            log('START', dstaddr)
          }
          if (!openConns[dstaddr].has(srcport)) {
            // we're not tracking this
            return
          }
          if (isFin) {
            openConns[dstaddr].delete(srcport)
            delete openPorts[dstaddr]
            log('FIN', dstaddr, connId)
            byteCounts[connId] = [0, 0]
          }
          if (isRst) {
            openConns[dstaddr].delete(srcport)
            delete openPorts[dstaddr]
            log('FIN', dstaddr, connId)
            byteCounts[connId] = [0, 0]
          }
        } else { // inbound
          connId = ret.info.dstport + ' ' + srcaddr
          if (!byteCounts[connId]) {
            byteCounts[connId] = [0, 0]
          }
          byteCounts[connId][0] += datalen
        }
      }
    }
  }
})

setInterval(function () {
  for (var conn in openConns) {
    var connPorts = openConns[conn].values()
    var data = {
      'dst': hostNames[conn],
      'count': openConns[conn].size,
      'name': openPorts[connPorts.next().value]
    }
    if (data['count'] === 0) {
      continue
    }
    console.log(sprintf('      %(dst)60s %(name)20s open: %(count)3i', data))
  }
}, 10 * 1000)
