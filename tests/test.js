"use strict";

const assert = require("assert");
const fs = require("fs");
const { resolve } = require("path");
const exec = require("child_process").exec;

const ethers = require("ethers");
const { compile } = require("@ethersproject/cli/solc");

const Takoyaki = require('./takoyaki');

const ens = require("./ens");
const { SourceMapper } = require("./source-mapper");

// Start Parity in dev mode:
//   /home/ricmoo> echo "\n" > test.pwds
//   /home/ricmoo> parity --config dev-insecure --unlock=0x00a329c0648769a73afac7f9381e08fb43dbea72 --password test.pwds -d ./test

let provider = null;
let admin = null;
let ABI = null;
let wallet = null;
let takoyakiContract = null;

const GRACE_PERIOD = 2;
const REGISTRATION_PERIOD = 12;
const MAX_COMMIT_BLOCKS = 10;
const WAIT_CANCEL_BLOCKS = 16;
const DEFAULT_FEE = ethers.utils.parseEther("0.1");

const fastForward = nMinutes => {
  return new Promise((resolve, reject) => {
    exec(`sudo date -s '${nMinutes} minutes'`, (error, stdout) => {
      if (error) {
        reject(error);
        return;
      }

      resolve(stdout);
    });
  });
};

before(async function() {
    // Compile Takoyaki Registrar
    console.log("Compiling TakoyakiRegistrar...");
    let source = fs.readFileSync(resolve(__dirname, "../contracts/TakoyakiRegistrar.sol")).toString();

    let sourceMapper = new SourceMapper(source);
    sourceMapper.set("MIN_COMMIT_BLOCKS", null);
    sourceMapper.set("MAX_COMMIT_BLOCKS", `${MAX_COMMIT_BLOCKS}`);
    sourceMapper.set("WAIT_CANCEL_BLOCKS", `${WAIT_CANCEL_BLOCKS}`);
    sourceMapper.set("REGISTRATION_PERIOD", "(12 minutes)");
    sourceMapper.set("GRACE_PERIOD", "(2 minutes)");

    let warnings = sourceMapper.warnings;
    if (warnings.length) {
        console.log(warnings);
        warnings.forEach((warning) =>{
            console.log("[Source Mapper] " + warning.line);
        });
        throw new Error("Errors during source mapping.");
    }

    let code = null;
    try {
        code = compile(sourceMapper.source, {
            optimize: true
        }).filter((contract) => (contract.name === "TakoyakiRegistrar"))[0];
    } catch (e) {
        console.log(e);
        e.errors.forEach((error) => {
            console.log(error);
        });
        throw new Error('Failed to compile TakoyakiRegistrar.sol');
    }
    ABI = code.interface;

    // Compile Wallet
    console.log("Compiling Wallet...");
    const walletSource = fs.readFileSync(resolve(__dirname, "../contracts/Wallet.sol")).toString();

    let walletSourceMapper = new SourceMapper(walletSource);
    let walletCode = null;
    try {
        walletCode = compile(walletSourceMapper.source, {
            optimize: true
        }).filter((contract) => (contract.name === "Wallet"))[0];
    } catch (e) {
        e.errors.forEach((error) => {
            console.log(error);
        });
        throw new Error('Failed to compile Wallet.sol');
    }

    // Deploy ENS
    console.log("Deploying ENS...");
    provider = await ens.prepareProvider("http://localhost:8545");
    let ensAddress = await provider.getNetwork().then((network) => network.ensAddress);

    // Fund the admin account
    admin = await ens.createSigner(provider);

    // @TODO: support this in ethers
    let defaultResolver = await provider.resolveName("resolver.eth");

    // Deploy Takoyaki Registrar
    console.log("Deploying TakoyakiRegistrar...");
    let contractFactory = new ethers.ContractFactory(ABI, code.bytecode, admin);
    let contract = await contractFactory.deploy(ensAddress, ethers.utils.namehash("takoyaki.eth"), defaultResolver, {
        gasLimit: 4300000
    });
    await contract.deployed();

    // Give takoyaki.eth to the Takoyaki Registrar (as the owner and resolver)
    await provider.register("takoyaki.eth", contract.address, contract.address);
    takoyakiContract = Takoyaki.connect(provider);

    // Deploy Wallet contract
    console.log("Deploying Wallet...");
    const walletFactory = new ethers.ContractFactory(walletCode.interface, walletCode.bytecode, admin);
    wallet = await walletFactory.deploy({ gasLimit: 4300000 });
    await wallet.deployed();

});

describe("Check Config", async function() {

    let expected = {
        "ens()":      () => (provider.getNetwork().then((network) => network.ensAddress)),
        "nodehash()": () => (ethers.utils.namehash("takoyaki.eth")),

        "admin()":           () => (admin.address),
        "defaultResolver()": () => (provider.resolveName("resolver.eth")),
        "fee()":             () => (ethers.utils.parseEther("0.1")),

        "name()":     () => ("Takoyaki"),
        "symbol()":   () => ("TAKO"),
        "decimals()": () => (0),
    }

    Object.keys(expected).forEach(function(key) {
        it(key, function() {
            let contract = new ethers.Contract("takoyaki.eth", ABI, provider);
            return contract.functions[key]().then((value) => {
                let expectedValue = expected[key]();
                if (!(expectedValue instanceof Promise)) {
                    expectedValue = Promise.resolve(expectedValue);
                }
                return expectedValue.then((expectedValue) => {
                    if (value.eq) {
                         assert.ok(value.eq(expectedValue), `${ key }: ${ value } !== ${ expectedValue }`)
                    } else {
                        assert.equal(value, expectedValue, `${ key }: ${ value } !== ${ expectedValue }`);
                    }
                });
            });
        });
    });

    it("ENS.owner(takoyaki.eth)", async function() {
        let ensAddress = provider.getNetwork().then((network) => network.ensAddress);
        let contract = new ethers.Contract(ensAddress, [ "function owner(bytes32) view returns (address)" ], provider);
        let owner = await contract.owner(ethers.utils.namehash("takoyaki.eth"));
        let resolvedAddress = await provider.resolveName("takoyaki.eth");
        assert.equal(owner, resolvedAddress, "owner is not TakoyakiRegistrar");
    });
});

describe("Admin Tasks", function() {
    describe("Withdraw Funds", function() {
        it("allows admin to withdraw", async function() {
           const takoyaki = Takoyaki.connect(admin);
           const tx = await takoyaki.withdraw("0");
           assert.doesNotReject(tx.wait().then(receipt => {
              const regex = /^0x[a-f0-9]{64}/;
              assert.ok(regex.test(receipt.transactionHash), "transaction hash is invalid");
           }));
        });

        it("prevents non-admin from  withdrawing", async function() {
           const signer = await provider.createSigner();
           const takoyaki = Takoyaki.connect(signer);
           const tx = await takoyaki.withdraw("0");
           assert.rejects(tx.wait().then(receipt => {
              assert.fail("non-admin should not be able to withdraw");
           }),
           { reason: 'transaction failed'});
        });
    });

});

describe("Name Registration (happy path)", function() {
    it("can register test.takoyaki.eth (no dust wallet)", async function() {
        let signer = await provider.createSigner();
        let takoyaki = Takoyaki.connect(signer);
        let salt = ethers.utils.keccak256(ethers.utils.randomBytes(32));

        let tx = await takoyaki.commit("test", signer.address, salt, ethers.constants.AddressZero, 0);
        let receipt = await tx.wait();
        // @TODO: check logs in receipt

        await provider.mineBlocks(5);

        tx = await takoyaki.reveal("test", signer.address, salt);
        receipt = await tx.wait();
        // @TODO: check logs in receipt

        let owner = await provider.resolveName("test.takoyaki.eth");
        assert.equal(owner, signer.address, "test.takoyaki.eth owner is not buyer");
    });

    it("can register test2.takoyaki.eth (with dust wallet)", async function() {
        let takoyaki = Takoyaki.connect(provider);

        let signerOwner = await provider.createSigner();
        let signerCommit = await provider.createSigner();
        let signerReveal = await provider.createSigner("0.0000000001");

        let salt = ethers.utils.keccak256(ethers.utils.randomBytes(32));

        let txs = await takoyaki.getTransactions("test2", signerOwner.address, salt, signerReveal.address);

        let tx = await signerCommit.sendTransaction(txs.commit);
        let receipt = await tx.wait();
        // @TODO: check logs in receipt

        await provider.mineBlocks(5);

        tx = await signerReveal.sendTransaction(txs.reveal);
        receipt = await tx.wait();
        // @TODO: check logs in receipt

        let owner = await provider.resolveName("test2.takoyaki.eth");
        assert.equal(owner, signerOwner.address, "test2.takoyaki.eth owner is not buyer");
    });
});

describe("Commits and reveals", function() {
    it('should allow multiple commits by different signers', async function() {
        const signer1 = await provider.createSigner();
        const signer2 = await provider.createSigner();
        const label = "dragon";
        let error = null;

        try {
            let takoyaki = Takoyaki.connect(signer1);
            const blindedCommit1 = await Takoyaki.submitBlindedCommit(
              provider,
              signer1,
              label
            );

            takoyaki = Takoyaki.connect(signer2);
            const blindedCommit2 = await Takoyaki.submitBlindedCommit(
              provider,
              signer2,
              label
            );

        } catch (err) {
             error = err;
        }

        assert.ok(error === null, "multiple commits should work");
    });

    it("Cannot reveal after MAX_COMMIT_BLOCKS", async function() {
        const label = "boom";
        const signer = await provider.createSigner();
        const takoyaki = Takoyaki.connect(signer);
        const salt = ethers.utils.keccak256(ethers.utils.randomBytes(32));
        let error = null;

        let tx = await takoyaki.commit(label, signer.address, salt, ethers.constants.AddressZero, 0);
        let receipt = await tx.wait();

        // fast forward past the max commit blocks
        await provider.mineBlocks(MAX_COMMIT_BLOCKS + 1);

        try {
            tx = await takoyaki.reveal(label, signer.address, salt);
            receipt = await tx.wait();
        } catch ( err ) {
            error = err;
        }

        assert.ok( error && error.code === 'CALL_EXCEPTION', "Reveal should fail past max commit blocks");

    });

    it('should fail subsequent reveal', async function() {
        const label = 'shiny';
        const signer1 = await provider.createSigner("0.22");
        const receipt1 = await Takoyaki.register(provider, signer1, label);

        const signer2 = await provider.createSigner("0.22");

        let error = null;
        try {
            const receipt2 = await Takoyaki.register(provider, signer2, label);
        } catch (err) {
            error = err;
        }

        assert.ok( error && error.code === 'CALL_EXCEPTION', "Second registration should fail");
    });

    it('should allow subsequent reveal if the name has expired and past grace period', async function() {
        this.timeout(0);

        const label = 'tree';
        let error = null;

        try {
            const signer1 = await provider.createSigner("0.22");
            const receipt1 = await Takoyaki.register(provider, signer1, label);

            await fastForward(REGISTRATION_PERIOD + GRACE_PERIOD + 1);

            const signer2 = await provider.createSigner("0.22");
            const receipt2 = await Takoyaki.register(provider, signer2, label);
        } catch (err) {
            error = err;
        }

        assert.ok( error === null, "Second registration should pass");
    });

    it('should fail subsequent reveal if the name has expired but within grace period', async function() {
        this.timeout(0);

        const label = 'treasure';
        let error = null;

        try {
            const signer1 = await provider.createSigner("0.22");
            const receipt1 = await Takoyaki.register(provider, signer1, label);

            await fastForward(REGISTRATION_PERIOD + 1);

            const signer2 = await provider.createSigner("0.22");
            const receipt2 = await Takoyaki.register(provider, signer2, label);
        } catch (err) {
            error = err;
        }

        assert.ok( error && error.code === 'CALL_EXCEPTION', "Second registration should fail");
    });
});

describe('Renew registration', function() {
  it('can renew after reveal', async function() {
    const label = 'bumble';
    const signer = await provider.createSigner("0.22");
    let receipt = await Takoyaki.register(provider, signer, label);

    const takoyaki = Takoyaki.connect(signer);
    const tokenId = Takoyaki.getTokenId(takoyaki, receipt);

    const tx = await takoyaki.renew(tokenId, { value: ethers.utils.parseEther("0.1") });
    await tx.wait();

    const token = await takoyaki.getTakoyaki(tokenId);
    assert.equal(
      token.status,
      2,
      `expect status to be 2 but got ${token.status}`
    );
  });
});

describe('Destroy registration', function() {
  it('can destroy after reveal', async function() {
    this.timeout(0);
    const label = 'klaus';
    let signer = await provider.createSigner();

    const takoyaki = Takoyaki.connect(signer);
    const receipt = await Takoyaki.register(provider, signer, label);
    const tokenId = Takoyaki.getTokenId(takoyaki, receipt);

    // fast forward to past grace period
    await fastForward(REGISTRATION_PERIOD + GRACE_PERIOD + 1);
    await provider.mineBlocks(1);

    const tx = await takoyaki.destroy(tokenId);
    await tx.wait();

    const token = await takoyaki.getTakoyaki(tokenId);
    assert.equal(
      token.status,
      0,
      `expect status to be 0 but got ${token.status}`
    );
  });
});

describe("syncUpkeepFee()", function() {
    let tokenId = null;
    let owner = null;
    let nonOwner = null;

    before(async function(){
        owner = await provider.createSigner("2");
        nonOwner = await provider.createSigner("2");
        const label = "circle";
        const receipt = await Takoyaki.register(provider, owner, label);
        tokenId = Takoyaki.getTokenId(takoyakiContract, receipt);
    });

    after(async function(){
        const takoyaki = Takoyaki.connect(admin);
        const tx = await takoyaki.setFee(DEFAULT_FEE);
        await tx.wait();
    });

    it("should work if called by token owner", async function() {
        let error = null;
        let updatedFee = null;

        try {
            updatedFee = await Takoyaki.syncUpkeepFee(admin, owner, tokenId);
        } catch (err) {
            error = err;
        }


        const token = await takoyakiContract.getTakoyaki(tokenId);

        assert.ok(error === null, "sync upkeep fee should not throw");
        assert.ok(updatedFee && token.upkeepFee.eq(updatedFee), "token should have new upkeep fee");
    });

    it("should work if called by non token owner", async function() {
        let error = null;
        let updatedFee = null;

        try {
            updatedFee = await Takoyaki.syncUpkeepFee(admin, admin, tokenId);
        } catch (err) {
            error = err;
        }


        const token = await takoyakiContract.getTakoyaki(tokenId);

        assert.ok(error === null, "sync upkeep fee should not throw");
        assert.ok(updatedFee !== null, "fee should be updated");
        assert.ok(token.upkeepFee.eq(updatedFee), "token should have new upkeep fee");
    });

    it("should fail for token that has expired", async function() {
        this.timeout(0);

        const originalFee = await takoyakiContract.getTakoyaki(tokenId).then(token => token.upkeepFee);

        await fastForward(REGISTRATION_PERIOD + 1);

        let error = null;
        let updatedFee = null;
        try {
            updatedFee = await Takoyaki.syncUpkeepFee(admin, admin, tokenId);
        } catch (err) {
            error = err;
        }

        assert.ok( error && error.code === 'CALL_EXCEPTION', "Sync fee should fail");

        const token = await takoyakiContract.getTakoyaki(tokenId);
        assert.ok(token.upkeepFee.eq(originalFee), "token should have same upkeep fee");
    });

    it("Called for invalid token", async function() {
        const takoyaki = Takoyaki.connect(owner);
        const syncTx = await takoyaki.syncUpkeepFee("333");
        let error = null;
        try {
            await syncTx.wait();
        } catch (err) {
            error = err;
        }

        assert.ok( error && error.code === 'CALL_EXCEPTION', "Sync fee should fail");
    });
});

describe("ERC-721 Operations", function() {
    let   signer;
    let   newOwner;

    before(async function(){
        signer = await provider.createSigner("5");
        newOwner = await provider.createSigner("2");
    });

    it(`can get blinded commitment`, async function() {
        const takoyaki = Takoyaki.connect(signer);
        const blindedCommit = await Takoyaki.submitBlindedCommit(
          provider,
          signer,
          'starlink'
        );

        const commitment = await takoyaki.getBlindedCommit(blindedCommit);
        assert.equal(commitment.payer, signer.address, 'not payer for ens');
        assert.ok(
          commitment.feePaid.eq(ethers.utils.parseEther('0.1')),
          'feePaid mismatch'
        );
    });

    it(`can cancel commitment`, async function() {
        const takoyaki = Takoyaki.connect(signer);
        const blindedCommit = await Takoyaki.submitBlindedCommit(
          provider,
          signer,
          'spiderman'
        );

        // can only cancel after n blocks
        await provider.mineBlocks(MAX_COMMIT_BLOCKS + WAIT_CANCEL_BLOCKS);

        const balance = await provider.getBalance(signer.address);

        const tx = await takoyaki.cancelCommitment(blindedCommit);
        const receipt = await tx.wait();

        const cancelEvent = Takoyaki.getEvent(takoyaki, receipt, 'Cancelled');
        assert.ok(cancelEvent);
        assert.ok(cancelEvent.values.length === 2);
        assert.equal(
          blindedCommit,
          cancelEvent.values[1],
          'blindedCommit mismatch'
        );

        const newBalance = await provider.getBalance(signer.address);
        assert.ok(newBalance.gt(balance), 'balance should be greater');
    });

    it(`Cannot cancel commitment if it had already been cancelled`, async function() {
        const takoyaki = Takoyaki.connect(signer);
        const label = "star";
        const blindedCommit = await Takoyaki.submitBlindedCommit(
          provider,
          signer,
          label
        );

        // can only cancel after n blocks
        await provider.mineBlocks(MAX_COMMIT_BLOCKS + WAIT_CANCEL_BLOCKS);

        const tx = await takoyaki.cancelCommitment(blindedCommit);
        const receipt = await tx.wait();

        const tx2 = await takoyaki.cancelCommitment(blindedCommit);
        let error = null;
        try {
            await tx2.wait();
        } catch (err) {
            error = err;
        }

        assert.ok( error && error.code === 'CALL_EXCEPTION', "cancellation should fail");

    });

    it(`Cannot cancel commitment if the takoyaki does not have enough balance`, async function() {
        const label = "forces";
        const blindedCommit = await Takoyaki.submitBlindedCommit(
          provider,
          signer,
          label
        );

        
        let takoyaki = Takoyaki.connect(admin);
        const balance = await provider.getBalance(takoyaki.address);
        const withdrawTx = await takoyaki.withdraw(balance);
        await withdrawTx.wait();
        
        // can only cancel after n blocks
        await provider.mineBlocks(MAX_COMMIT_BLOCKS + WAIT_CANCEL_BLOCKS);

        takoyaki = Takoyaki.connect(signer);
        const tx = await takoyaki.cancelCommitment(blindedCommit);
        let error = null;
        try {
            await tx.wait();
        } catch (err) {
            error = err;
        }

        assert.ok( error && error.code === 'CALL_EXCEPTION', "cancellation should fail");

    });

    it("Cannot cancel commitment before MAX_COMMIT_BLOCKS + MAX_CANCEl_BLOCKS has been mined", async function() {
        const label = "flash";
        const takoyaki = Takoyaki.connect(signer);
        const blindedCommit = await Takoyaki.submitBlindedCommit(
          provider,
          signer,
          label
        );

        const tx = await takoyaki.cancelCommitment(blindedCommit);
        let error = null;
        try {
           const receipt = await tx.wait();
        } catch ( err ) {
          error = err;
        }

        assert.ok( error && error.code === 'CALL_EXCEPTION', "cancellation should fail");
    });

    it("Cannot cancel commitment after revelation", async function() {
        const label = "gameofthrone";
        const receipt = await Takoyaki.register(provider, signer, label);
        const takoyaki = Takoyaki.connect(signer);
        const salt = await provider.getTransaction(receipt.transactionHash).then(tx => {
            const parsedTx = takoyaki.interface.parseTransaction(tx);
            assert.ok(parsedTx.args.length === 3);
            return parsedTx.args[2];
        });
        const blindedCommit = await takoyaki.makeBlindedCommitment(label, signer.address, salt);
        const tx = await takoyaki.cancelCommitment(blindedCommit);
        let error = null;
        try {
           const receipt = await tx.wait();
        } catch ( err ) {
          error = err;
        }

        assert.ok( error && error.code === 'CALL_EXCEPTION', "cancellation should fail");
    });

    it("Cannot cancel commitment owned by others", async function() {
        const label = "champion";
        const blindedCommit = await Takoyaki.submitBlindedCommit(
          provider,
          signer,
          label
        );

        // can only cancel after n blocks
        await provider.mineBlocks(MAX_COMMIT_BLOCKS + WAIT_CANCEL_BLOCKS);

        const takoyaki = Takoyaki.connect(newOwner);
        const tx = await takoyaki.cancelCommitment(blindedCommit);
        let error = null;
        try {
           const receipt = await tx.wait();
        } catch ( err ) {
          error = err;
        }

        assert.ok( error && error.code === 'CALL_EXCEPTION', "cancellation should fail");
    });

    it(`can register with correct tokenURI`, async function() {
        const uriPrefix = 'https://takoyaki.nftmd.com/json/';
        const label = 'zelda';
        const ensName = `${label}.takoyaki.eth`;

        const receipt = await Takoyaki.register(provider, signer, label);

        const tokenId = Takoyaki.getTokenId(takoyakiContract, receipt);

        const tokenOwner = await takoyakiContract.ownerOf(tokenId);
        assert.equal(tokenOwner, signer.address);

        const tokenURI = await takoyakiContract.tokenURI(tokenId.toHexString());
        assert.equal(
          tokenURI,
          `${uriPrefix}318ae6d0db4a394a61e1e763192966436a00f74c1f87b065808bdb7205125bcc`,
          'tokenURI mismatch'
        );

        const tokenURIFromContract = await takoyakiContract.functions.tokenURI(tokenId);
        assert.equal(
          tokenURIFromContract,
          tokenURI,
          'tokenURI and tokenURIFromContract mismatch'
        );

        const owner = await provider.resolveName(ensName);
        assert.equal(owner, signer.address, `${ensName} owner is not buyer`);
    });

    it('can safeTransferFrom without data', async function() {
        const receipt = await Takoyaki.register(provider, signer, 'transfer');
        const tokenId = Takoyaki.getTokenId(takoyakiContract, receipt);

        // transfer the token to newOwner
        await Takoyaki.safeTransfer(signer, newOwner, tokenId);
        const tokenOwner = await takoyakiContract.ownerOf(tokenId);

        // after transfer, the newOwner should own the token
        assert.equal(tokenOwner, newOwner.address);
    });

    it('can safeTransferFrom with data', async function() {
        const receipt = await Takoyaki.register(provider, signer, 'transferData');
        const tokenId = Takoyaki.getTokenId(takoyakiContract, receipt);

        // transfer to a wallet contract that can accept data
        // '0xd09de08a' is the call to wallet.increment()
        await Takoyaki.safeTransfer(signer, wallet, tokenId, '0xd09de08a');
        const tokenOwner = await takoyakiContract.ownerOf(tokenId);

        // after transfer, the wallet should own the token
        assert.equal(tokenOwner, wallet.address);

        const count = await wallet.count();
        assert.equal(count, 1, 'wallet count should equal 1');
    });

    it('safeTransferFrom with wrong owner should throw', async function() {
        const receipt = await Takoyaki.register(provider, signer, 'wrongOwner');
        const tokenId = Takoyaki.getTokenId(takoyakiContract, receipt);

        let error = null;
        try {
            await Takoyaki.safeTransfer(newOwner, wallet, tokenId);
        } catch (err) {
            error = err;
        }

        if (!error) {
            assert.fail('safeTransfer with wrong owner should fail but did not!!!');
        }

        assert.ok(error.code === 'CALL_EXCEPTION');
    });

    it('getTakoyaki() during grace period should return status 1', async function() {
        this.timeout(0);

        const receipt = await Takoyaki.register(provider, signer, 'grace');

        // fast forward to grace period
        await fastForward(REGISTRATION_PERIOD + 1);
        await provider.mineBlocks(1);

        const tokenId = Takoyaki.getTokenId(takoyakiContract, receipt);
        const token = await takoyakiContract.getTakoyaki(tokenId);
        assert.equal(token.status, 1, 'status should be in grace period');
    });
});

describe("Approval", function() {
     it("happy path", async function() {
        const label = 'throne';
        const owner = await provider.createSigner();
        const receipt = await Takoyaki.register(provider, owner, label);

        const takoyaki = Takoyaki.connect(owner);
        const tokenId = Takoyaki.getTokenId(takoyaki, receipt);
        let approved = await takoyaki.getApproved(tokenId);
        assert.ok(approved === ethers.constants.AddressZero, "approved should default to zero");

        const newOwner = await provider.createSigner();
        const approveReceipt = await takoyaki.approve(newOwner.address, tokenId);
        approved = await takoyaki.getApproved(tokenId);
        assert.ok(approved === newOwner.address, "approved should equal to newOwner");
     });
});

describe("Name Validatation", function() {
    describe("Valid Names", function() {
        [ "loo", "ricmoo", "ricmoo01234567890123",
          "0yfoobar", "1xfoobar", "1Xfoobar",
          "12345", "hello", "lo", "r"
        ].forEach((name) => {
            it(name, function() {
                let contract = new ethers.Contract("takoyaki.eth", ABI, provider);
                contract.isValidLabel(name).then((isValid) => {
                    assert.ok(isValid, name);
                });
            });
        });
    });

    describe("Invalid Names", function() {
        [ "ricmoo012345678901234",
          "0xfoobar", "0Xfoobar"
        ].forEach((name) => {
            it(name, function() {
                let contract = new ethers.Contract("takoyaki.eth", ABI, provider);
                contract.isValidLabel(name).then((isValid) => {
                    assert.ok(!isValid, name);
                });
            });
        });
    });

    describe("Punycode Conversion", function() {
    })
});

