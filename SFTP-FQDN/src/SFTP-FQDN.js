const AWS = require("aws-sdk");
const dnsPromises = require('dns').promises;

const networkfirewall = new AWS.NetworkFirewall();

const getAddresses = async function(fqdn){
  let res = await dnsPromises.resolve4(fqdn);
  return res.map((line)=> {return line + "/32"});
};

const updateRules = async function (ruleGroup, fqdn, addresses) {
  let params = ruleGroup;
  params.RuleGroupName = params.RuleGroupResponse.RuleGroupName;
  params.Description = params.RuleGroupResponse.Description;
  params.Type = params.RuleGroupResponse.Type;
  delete params.Capacity;
  delete params.RuleGroupResponse;
  
  let rulesString = "# Last autofetched by Lambda: " + new Date().toUTCString() + "\n";
  rulesString += "# Fetched addresses for: " + fqdn + " stored as Variable: $SFTPFQDN\n";
  addresses.forEach (address => {
    rulesString += "# " + address + "\n";
  });
  rulesString += 'pass tcp any any -> $SFTPFQDN 22 (msg:"Allow access to ' + fqdn + '"; sid:1001;)';
  
  params.RuleGroup.RulesSource.RulesString = rulesString;
  params.RuleGroup.RuleVariables.IPSets.SFTPFQDN.Definition = addresses;

  console.log("Updating rules...");
  let res = await networkfirewall.updateRuleGroup(params).promise();
  if (res) {
    console.log("Updated '" + params.RuleGroupName + "'.");
  } else {
    console.log("Error updating the rules for '" + params.RuleGroupName + "'...");
  }
  
  return;
};

exports.handler = async (event, context) => {
  var rg = {Type: "STATEFUL", RuleGroupArn: '<YOUR-ARN-GOES-HERE>'};
  const fqdn = "<YOUR-FQDN-GOES-HERE>";
  
  let addresses = await getAddresses(fqdn);
  if (addresses) {
    console.log("Searching Rule Groups for " + rg.RuleGroupArn + "...");
    let res = await networkfirewall.describeRuleGroup(rg).promise();
    if (res.RuleGroupResponse) {
      console.log("Found matching Rule Group...");
      await updateRules(res, fqdn, addresses);
      
    } else {
      console.log("ERROR: No matching Rule Group found...");
    }  
  } else {
    console.log("Could not resolve addresses for fqdn: " + fqdn);
  }
  
  return;
};
