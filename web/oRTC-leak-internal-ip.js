let ipAddresses = [];

var oRTCIceGatherer = new RTCIceGatherer({ "gatherPolicy": "all", "iceServers": [] });
oRTCIceGatherer.onlocalcandidate = function (oEvent) {
  if(oEvent.candidate.type == "host") { 
    ipAddresses.push(oEvent.candidate.ip);
  }
};

setTimeout(function() {
  console.log(ipAddresses.toString());
}, 500);