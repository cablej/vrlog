var axios = require("axios");

const host = "http://54.201.124.77:8084/";

function printTimes(times, name) {
  if (times.length > 0) {
    console.log("Operation: " + name);
    console.log(
      "Average time: " + times.reduce((a, b) => a + b) / times.length
    );
    console.log("Total time: " + times.reduce((a, b) => a + b));
  }
}

async function testAddVoter(upTo) {
  resp = await axios.get(host + "version");
  version = parseInt(resp.data.version);
  times = {
    addVoter: [],
    getVoter: [],
    membershipProof: [],
    verifyMembership: []
  };
  while (version < upTo) {
    version++;
    body = {
      firstName: "Test",
      lastName: "Test",
      ssn: "1234",
      id: version.toString(),
      status: "active"
    };
    resp = await axios.post(host + "voter", body);
    times["addVoter"].push(parseInt(resp.headers["response-time"]));

    id = resp.data.id;
    resp = await axios.get(host + "voter?id=" + id);
    times["getVoter"].push(parseInt(resp.headers["response-time"]));

    resp = await axios.get(host + "voter/prove?id=" + id);
    times["membershipProof"].push(parseInt(resp.headers["response-time"]));

    resp = await axios.get(host + "voter/prove?id=" + id);
    times["membershipProof"].push(parseInt(resp.headers["response-time"]));

    resp = await axios.post(host + "voter/verify", resp.data);
    times["verifyMembership"].push(parseInt(resp.headers["response-time"]));
  }
  for (var type in times) {
    printTimes(times[type], type + " up to " + upTo.toString());
  }
}

async function testVerifyAppendOnly() {
  resp = await axios.get(host + "version");
  version = parseInt(resp.data.version);
  times = {
    proveAppendOnly: [],
    verifyAppendOnly: []
  };

  firstSize = 0;
  resp = await axios.get(host + "proveAppendOnly?first_tree_size=" + firstSize);
  times["proveAppendOnly"].push(parseInt(resp.headers["response-time"]));

  resp = await axios.post(host + "verifyAppendOnly", resp.data);
  times["verifyAppendOnly"].push(parseInt(resp.headers["response-time"]));

  for (var type in times) {
    printTimes(times[type], type);
  }
}

async function testSuite() {
  await testAddVoter(80);
  await testVerifyAppendOnly();
}

testSuite();
