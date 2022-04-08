const AWS = require("aws-sdk");
const response = require('cfn-response');
const https = require("https");
let listOfIps = [], listHeader = [];
const networkfirewall = new AWS.NetworkFirewall();

const rulesUrl = "https://geoip.linode.com/";
const rgARN = "<REPLACE-ME-WITH-YOUR-RG-ARN>"

function fetchIPs() {
  console.log("Fetching the list of IP addresses...");
  return new Promise((resolve, reject) => {
    let dataString = '';
    let post_req = https.request(rulesUrl, (res) => {
      res.setEncoding("utf8");
      res.on('data', chunk => {
        dataString += chunk;
      });
      res.on('end', () => {
        //initial array creation
        listOfIps = dataString.split(/\r?\n/);
        //strip out the header
        listHeader = listOfIps.filter((line) => line.match(/^#+/));
        //extract IPv4 lines
        listOfIps = listOfIps.filter((line) => line.match(/^(\d+(\.|$)){3}(\d+)/));
        //create objects from the IPv4 Data
        listOfIps = listOfIps.map(s => {
          let items = s.split(",");
          return JSON.parse('{"ip":"' + items[0] + '","country":"' + items[1] + '","subdivision":"' + items[2] + '","city":"' + items[3] + '"}');
        });
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
  params.Description = "Dynamic list using data fetched from" + rulesUrl;
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

  let rulesString = "# RG Last updated: " + new Date().toUTCString() + "\n";
  rulesString += "# Using a list of " + listOfIps.length + " IP addresses\n";
  rulesString += "# ------------------ Following section fetched from " + rulesUrl + " -----------------------\n";
  listHeader.forEach((line) => {rulesString += line + "\n"});
  rulesString += "# ------------------ End section fetched from " + rulesUrl + " -----------------------\n";
  
  listOfIps.forEach((obj, index) => {
    //Construct the rule (example: drop ip $HOME_NET any -> 104.16.248.0/24 any (msg:"drop resulting from traffic relating to a Linode address from US-Atlanta"; sid:1;)
    rulesString += type + ` ip $HOME_NET any -> ` + obj.ip + ' any (msg:"' + type + ' resulting from traffic relating to a Linode address from ' + obj.country + '-' + obj.city + '"; rev:1; sid:102' + index + ';)\n';
  });

  ruleGroup.RuleGroup.RulesSource.RulesString = rulesString;
  await updateRules(ruleGroup);

  return;
};

exports.handler = async (event, context) => {
    if (event.RequestType == "Delete") {
      await response.send(event, context, "SUCCESS");
      return;
  }

  let params = {Type: "STATEFUL", RuleGroupArn: rgARN};
  
  console.log("Searching for matching Rule Group...");
  let res = await networkfirewall.describeRuleGroup(params).promise();

  if (res.RuleGroupResponse) {
    console.log("Found Rule Group...");
    await createRules(res,"alert");
    if (event.ResponseURL) await response.send(event, context, response.SUCCESS);
  } else {
    console.log("ERROR: No matching Rule Group found...");
    if (event.ResponseURL) await response.send(event, context, response.FAILED);
  }
  
  return;
};
