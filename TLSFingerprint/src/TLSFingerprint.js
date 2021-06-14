var AWS = require("aws-sdk");
const https = require("https");
const tls = require('tls');

const nf = new AWS.NetworkFirewall();

function genSid() {
  return Math.floor(Math.random() * 1000000000);
}

async function getDomains(arn){
  let params = {Type: "STATEFUL", RuleGroupArn: arn};
  let res = await nf.describeRuleGroup(params).promise();
  if (res.RuleGroupResponse) {
    console.log("Found source rulegroup");
    let domains = (res.RuleGroup.RulesSource.RulesSourceList.Targets);
    return domains;
  } else {
    console.log("ERROR: No matching Rule Group found");
  } 
  return;
}

function fetchCert(host) {
  let fCert = {subject: {CN: ""}, fingerprint: ""};
  const options = {
    hostname: host,
    port: 443,
    path: "/",
    method: 'GET',
    checkServerIdentity: function(host, cert) {
      const err = tls.checkServerIdentity(host, cert);
      if (err) {
        return err;
      }
      fCert.subject.CN = cert.subject.CN;
      fCert.fingerprint = cert.fingerprint.toLowerCase();
    }
  };
  
  options.agent = new https.Agent(options);
  
  return new Promise((resolve, reject) => {
    let req = https.request(options, (res) => {
      res.on('data', d => {});
    
      res.on('end', () => {
        console.log('  Fetching from:', host);
        console.log('    Subject Common Name:', fCert.subject.CN);
        console.log('    Certificate SHA-1 fingerprint:', fCert.fingerprint);
        resolve(fCert);
      });

      res.on('error', (err) => {
        reject(err);
      });

    });
    
    req.end();
  });
}

async function updateRuleGroup(newRule){
  let params = {Type: "STATEFUL", RuleGroupArn: '<REPLACE-ME-WITH-THE-ARN-OF-YOUR-TLS-RULE-GROUP>'};
  let res = await nf.describeRuleGroup(params).promise();
  if (res.RuleGroupResponse) {
    console.log("Found destination rulegroup");
    res.RuleGroup.RulesSource.RulesString = newRule;
    delete res.Capacity;
    res.RuleGroupName = res.RuleGroupResponse.RuleGroupName;
    res.Description = res.RuleGroupResponse.Description;
    res.Type = res.RuleGroupResponse.Type;
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

  let sourceArn = '<REPLACE-ME-WITH-THE-ARN-OF-YOUR-SNI-RULE-GROUP>';
  console.log("Fetch a list of domains from: ", sourceArn);
  let domains = await getDomains(sourceArn);
  
  if (domains) {
    console.log("Using a list of: " + domains.length + " domains");
    let newRule = '# This rule is automatically managed by a Lambda\n# Last updated: ' + new Date().toUTCString() + "\n";
    
    for (let index = 0; index < domains.length; index++) {
      let fCert = await fetchCert(domains[index]);
      if (fCert) {
        newRule += 'pass tls $EXTERNAL_NET any -> $HOME_NET any (msg:"Allow https://' + domains[index] + '/"; tls.fingerprint:"' + fCert.fingerprint + '"; sid:' + genSid() + '; rev:1;)\n';
      } else {
        newRule += '# ERROR: Unable to retrieve a fingerprint for: ' + domains[index] + '\n';
      }
    }

    newRule += 'drop tls $EXTERNAL_NET any -> $HOME_NET any (msg:"Drop all other TLS fingerprints"; tls.fingerprint:":"; sid:1; rev:1;)';
    
    await updateRuleGroup(newRule);
  } else {
    console.log("Error fetching a list of domains from: ", sourceArn);
  }
  
  return;
};
