var AWS = require("aws-sdk");
const https = require("https");

const hostfileUrl = "https://urlhaus.abuse.ch/downloads/hostfile/";

const nf = new AWS.NetworkFirewall();

async function getDomains (){
  var listOfDomains = [];
    console.log("Fetching the list of domains from " + hostfileUrl);
    return new Promise((resolve, reject) => {
      let dataString = '';
      let post_req = https.request(hostfileUrl, (res) => {
        res.setEncoding("utf8");
        res.on('data', chunk => {
          dataString += chunk;
        });
        res.on('end', () => {
          //console.log(dataString);
          listOfDomains = dataString
            .split(/\r?\n/)
            .filter((line) => line.match(/^\d+/))
            .map((line)=> {return line.replace(/127.0.0.1\t/,'').toLowerCase()})
            .filter((line) => line.match(/^(?!:\/\/)(?=.{1,255}$)((.{1,63}\.){1,127}(?![0-9]*$)[a-z0-9-]+\.?)$/));
          console.log("Fetched " + listOfDomains.length + " Domains");
          resolve(listOfDomains);
        });
        res.on('error', (err) => {
          reject(err);
        });
      });
      post_req.end();
    });
}

async function updateRuleGroup(arn, domains){
  let params = {Type: "STATEFUL", RuleGroupArn: arn};
  let res = await nf.describeRuleGroup(params).promise();
  if (res.RuleGroupResponse) {
    console.log("Found destination rulegroup");
    res.RuleGroup.RulesSource.RulesSourceList.Targets = domains;
    res.RuleGroupName = res.RuleGroupResponse.RuleGroupName;
    res.Description = "Last updated: " + new Date().toUTCString() + " -- The CloudWatch Events Rule: AbuseCHHostfileRulegroupHourlyTrigger, triggers a daily update of this list.";
    res.Type = res.RuleGroupResponse.Type;
    delete res.Capacity;
    delete res.RuleGroupResponse;

    console.log("Updating rules");
    let result = await nf.updateRuleGroup(res).promise();
    if (result) {
      console.log("Updated '" + res.RuleGroupName);
    } else {
      console.log("Error updating '" + res.RuleGroupName + "'...");
    }
  } else {
    console.log("No matching Rule Group found");
  } 
  return;
}

exports.handler = async (event, context) => {

  let sourceArn = '<REPLACE-ME-WITH-THE-ARN-OF-YOUR-RULE-GROUP>';
  let domains = await getDomains(sourceArn);
  
  if (domains) {
    console.log("Using a list of: " + domains.length + " domains");
    
    await updateRuleGroup(sourceArn, domains);
  } else {
    console.log("Error fetching a list of domains from: ", sourceArn);
  }
  
  return;
};
