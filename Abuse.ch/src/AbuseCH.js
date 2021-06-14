var AWS = require("aws-sdk");
var https = require("https");
var listOfRules = [];
var listOfRules2 = [];
var ruleHeader = [];
const url = "https://sslbl.abuse.ch/blacklist/sslblacklist_tls_cert.rules";

const networkfirewall = new AWS.NetworkFirewall();

function fetchRules() {
  console.log("Fetching the list of rules...");
  return new Promise((resolve, reject) => {
    let dataString = '';
    let post_req = https.request(url, (res) => {
      res.setEncoding("utf8");
      res.on('data', chunk => {
        dataString += chunk;
      });
      res.on('end', () => {
        listOfRules = dataString.split(/\r?\n/);
        console.log("Fetched rules...");
        resolve();
      });
      res.on('error', (err) => {
        reject(err);
      });
    });
    post_req.end();
  });
}

let updateRules = async function (ruleGroup,newRules,part) {
  let params = ruleGroup;
  delete params.Capacity;
  params.RuleGroupName = params.RuleGroupResponse.RuleGroupName;
  params.Description = params.RuleGroupResponse.Description;
  params.Type = params.RuleGroupResponse.Type;
  delete params.RuleGroupResponse;
  let rulesString = "# Last autofetched by Lambda: " + new Date().toUTCString() + "\n# Part " + part + " of 2\n";
  rulesString += ruleHeader.join("\n") + "\n";
  rulesString += newRules.join("\n");
  params.RuleGroup.RulesSource.RulesString = rulesString;

  console.log("Updating rules...");
  let res = await networkfirewall.updateRuleGroup(params).promise();
  if (res) {
    console.log("Updated '" + params.RuleGroupName + "'.");
  } else {
    console.log("Error updating the rules for '" + params.RuleGroupName + "'...");
  }
  return;
};

let createRules = async function (action) {
  if (listOfRules.length == 0) {
    await fetchRules();
  } else {
    console.log("Using recently fetched list of rules...");
  }

  if (!ruleHeader.length) {
    ruleHeader = listOfRules.filter(line => line.substring(0,1) == "#");
    ruleHeader.splice(ruleHeader.length-2, ruleHeader.length-1);
  }

  if (action == 'drop') listOfRules = listOfRules.map(rule => rule.replace("alert ", "drop ").replace(" detected", " dropped"));
  listOfRules = listOfRules.slice(ruleHeader.length+1,listOfRules.length-1); //strip header and footer
  listOfRules2 = listOfRules.splice(Math.ceil(listOfRules.length / 2));

  return;
};

exports.handler = async (event, context) => {

  var rg1 = {Type: "STATEFUL", RuleGroupArn: '<REPLACE-ME-WITH-THE-ARN-OF-YOUR-1ST-RULE-GROUP>'};
  var rg2 = {Type: "STATEFUL", RuleGroupArn: '<REPLACE-ME-WITH-THE-ARN-OF-YOUR-2ND-RULE-GROUP>'};
  
  await createRules('drop');
  
  console.log("Searching Rule Groups for " + rg1.RuleGroupArn + "...");
  let res = await networkfirewall.describeRuleGroup(rg1).promise();
  if (res.RuleGroupResponse) {
    console.log("Found matching Rule Group...");
    await updateRules(res,listOfRules,"1");
  } else {
    console.log("ERROR: No matching Rule Group found...");
  }
  
  console.log("Searching Rule Groups for " + rg2.RuleGroupArn + "...");
  res = await networkfirewall.describeRuleGroup(rg2).promise();
  if (res.RuleGroupResponse) {
    console.log("Found matching Rule Group...");
    await updateRules(res,listOfRules2,"2");
  } else {
    console.log("ERROR: No matching Rule Group found...");
  }
  return;
};
