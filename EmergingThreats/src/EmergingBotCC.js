var AWS = require("aws-sdk");
var https = require("https");
var listOfRules = [];
const url = "https://rules.emergingthreats.net/blockrules/emerging-botcc.suricata.rules";

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

let updateRules = async function (ruleGroup,newRules) {
  let params = ruleGroup;
  delete params.Capacity;
  params.RuleGroupName = params.RuleGroupResponse.RuleGroupName;
  params.Description = params.RuleGroupResponse.Description;
  params.Type = params.RuleGroupResponse.Type;
  delete params.RuleGroupResponse;
  let rulesString = "# Last autofetched by Lambda: " + new Date().toUTCString() + "\n";
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

  if (action == 'drop') listOfRules = listOfRules.map(rule => rule.replace("alert ", "drop "));

  return;
};

exports.handler = async (event, context) => {

  var rg = {Type: "STATEFUL", RuleGroupArn: '<Replace-With-Your-RG-ARN>'};
  
  await createRules('drop');
  
  console.log("Searching Rule Groups for " + rg.RuleGroupArn + "...");
  let res = await networkfirewall.describeRuleGroup(rg).promise();
  if (res.RuleGroupResponse) {
    console.log("Found matching Rule Group...");
    await updateRules(res,listOfRules);
  } else {
    console.log("ERROR: No matching Rule Group found...");
  }
  
  return;
};
