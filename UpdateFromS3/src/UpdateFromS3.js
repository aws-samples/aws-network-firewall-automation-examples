const AWS = require("aws-sdk");
const s3 = new AWS.S3();
const networkfirewall = new AWS.NetworkFirewall();

async function readFromS3(bucket, key){
  var params = {
    Bucket: bucket,
    Key: key
  };
  
  let res = await s3.getObject(params, function(err, data) {
    if (err) console.log(err, err.stack); // an error occurred
    else     return data;           // successful response
  }).promise();
  
  return res.Body.toString();
}

let updateRules = async function (ruleGroup) {
  let params = ruleGroup;
  delete params.Capacity;
  params.RuleGroupName = params.RuleGroupResponse.RuleGroupName;
  params.Description = params.RuleGroupResponse.Description;
  params.Type = params.RuleGroupResponse.Type;
  delete params.RuleGroupResponse;

  console.log("Updating rules...");
  let res = await networkfirewall.updateRuleGroup(params).promise();
  if (res) {
    console.log("Updated '" + params.RuleGroupName + "'.");
  } else {
    console.log(
      "Error updating the rules for '" + params.RuleGroupName + "'..."
    );
  }
  return;
};

let createRules = async function (ruleGroup, rules) {
 
  let rulesString = "# Last updated: " + new Date().toUTCString() + "\n";
  rulesString += rules;
  ruleGroup.RuleGroup.RulesSource.RulesString = rulesString;
  await updateRules(ruleGroup);

  return;
};

exports.handler = async (event, context) => {
  let obj = (event.Records[0].s3);
  let params = { Type: "STATEFUL", RuleGroupArn: "<REPLACE WITH YOUR RG ARN" };

  let rules = await readFromS3(obj.bucket.name, obj.object.key);
  console.log("Searching for Rule Group...");
  let res = await networkfirewall.describeRuleGroup(params).promise();
  if (res.RuleGroupResponse) {
    console.log("Found Rule Group...");
    await createRules(res, rules);
  } else {
    console.log("ERROR: No matching Rule Group found...");
  }
  return;
};