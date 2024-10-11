// DEPRECATED - but left for historical context
// This was based on Node 14 and will not work with Node 16 or greater
// Node 16 or great also requires v3 of the AWS SDK

var AWS = require("aws-sdk");
var https = require("https");
var listOfIps = [];

const TorProjectUrl = "https://check.torproject.org/exit-addresses";

const networkfirewall = new AWS.NetworkFirewall();

function fetchIPs() {
  console.log("Fetching the list of IP addresses...");
  return new Promise((resolve, reject) => {
    
    let dataString = '';
    let post_req = https.request(TorProjectUrl, (res) => {
      res.setEncoding("utf8");
      res.on('data', chunk => {
        dataString += chunk;
      });
      res.on('end', () => {
        listOfIps = dataString
          .split(/\r?\n/)
          .filter((line) => line.match(/ExitAddress /))
          .map(s => s.split(" ")[1]);
        console.log("Fetched " + listOfIps.length + " IP addresses...");
        resolve();
      });
      res.on('error', (err) => {
        reject(err);
      });
    });
    post_req.end();
  });
}

let updateRules = async function (ruleGroup) {
  let params = ruleGroup;
  delete params.Capacity;
  params.RuleGroupName = params.RuleGroupResponse.RuleGroupName;
  params.Type = params.RuleGroupResponse.Type;
  delete params.RuleGroupResponse;

  console.log("Updating rules...");
  let res = await networkfirewall.updateRuleGroup(params).promise();
  if (res) {
    console.log("Updated '" + params.RuleGroupName + "'.");
  } else {
    console.log("Error updating the rules for '" + params.RuleGroupName + "'...");
  }
  return;
};

let createRules = async function (ruleGroup, type) {
  if (listOfIps.length == 0) {
    await fetchIPs();
  } else {
    console.log("Using recently fetched list of " + listOfIps.length + " IP addresses...");
  }

  let rulesString = "# Last updated: " + new Date().toUTCString() + "\n";
  rulesString += "# Using a list of " + listOfIps.length + " IP addresses\n";
  
  listOfIps.forEach((ip, index) => {
    rulesString += type + ' ip ' + ip + ' any -> any any (msg:"' + type + ' emerging threats traffic from ' + ip + '"; rev:1; sid:55' + index + ';)\n';
    rulesString += type + ' ip any any -> ' + ip + ' any (msg:"' + type + ' emerging threats traffic to ' + ip + '"; rev:1; sid:66' + index + ';)\n';
  });

  ruleGroup.RuleGroup.RulesSource.RulesString = rulesString;
  await updateRules(ruleGroup);

  return;
};

exports.handler = async (event, context) => {

  var params = {Type: "STATEFUL", RuleGroupArn: 'arn:aws:network-firewall:us-east-1:442338576812:stateful-rulegroup/tor-t1-AutoUpdating-TorProjectIPList-drop'};
  
  console.log("Searching for Rule Groups...");
  let res = await networkfirewall.describeRuleGroup(params).promise();
  if (res.RuleGroupResponse) {
    console.log("Found Rule Group...");
    await createRules(res,"drop");
  } else {
    console.log("ERROR: No matching Rule Group found...");
  }
  
  return;
};
