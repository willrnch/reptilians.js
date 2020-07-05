const EventEmitter = require('events');
const _ = require('lodash');
const HID = require('node-hid');

const Web3 = require('web3');
const BN = require('bn.js');
const ethjsUtil = require('ethjs-util');
const { ethers } = require("ethers");
const ethereumjsUtil = require("ethereumjs-util");

const Touch = require('./Touch.json');
const TOUCH_CONTRACT_ADDRESS = '0x0213DEc9C5eEC5AFc71Df8Fad4C39b3876F57C14';

const ETH_ADDRESS_SIZE = 20;

const VENDOR_ID = 0x483;
const PRODUCT_ID = 0xa2ca;

const secp256k1N = new BN('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 16);
const secp256k1halfN = secp256k1N.div(new BN(2));

class Key extends EventEmitter {
  static HID_PACKET_SIZE = 64;

  static CMD = {
    HELLO: 0x0,
    RESET: 0x1,
    CREATE_KEY: 0x2,
    DUMP_KEYS: 0x3,
    DELETE: 0x4,
    SIGN: 0x5
  };

  static RES = {
    KEY_CREATED: 0x1,
    DUMP_KEYS: 0x2,
    SIGN: 0x3,
    DONE: 0xFF
  };

  static fromHID() {
    const device = new HID.HID(VENDOR_ID, PRODUCT_ID);
    return new Key(device);
  }

  constructor(device) {
    super();

    this.device = device;

    device.on('data', (data) => {
      switch (data[0]) {
        case Key.RES.KEY_CREATED:
          this.emit('key-created', data.slice(1));
          break;

        case Key.RES.DUMP_KEYS:
          this.emit('dump-keys', data.slice(1));
          break;

        case Key.RES.SIGN:
          this.emit('sign', data.slice(1));
          break;

        case Key.RES.DONE:
          this.emit('done');
          break;
      }
    });
  }

  createKey(index) {
    return new Promise((resolve) => {
      let address = null;
      this.once('key-created', (buff) => {
        address = `0x${buff.slice(0, ETH_ADDRESS_SIZE).toString('hex')}`;
      });

      this.once('done', () => {
        resolve(address);
      });

      const buff = _.fill(new Array(Key.HID_PACKET_SIZE), 0);
      buff[0] = Key.CMD.CREATE_KEY;
      buff[1] = index;
      this.device.write(buff);
    });
  }

  deleteKey(index) {
    return new Promise((resolve) => {
      this.once('done', () => {
        resolve();
      });

      const buff = _.fill(new Array(Key.HID_PACKET_SIZE), 0);
      buff[0] = Key.CMD.DELETE;
      buff[1] = index;

      this.device.write(buff);
    });
  }

  sign(index, payload) {
    return new Promise((resolve) => {
      const res = [];

      const onSign = (buff) => {
        res.push(buff);
      };

      this.on('sign', onSign);
      this.once('done', () => {
        this.removeListener('sign', onSign);

        const signature = Buffer.concat([
          res[0].slice(0, 32),
          res[1].slice(0, 32),
        ]);

        resolve(signature);
      });

      const buff = _.fill(new Array(Key.HID_PACKET_SIZE), 0);
      buff[0] = Key.CMD.SIGN;
      buff[1] = index;

      for (let i = 0; i < 32; ++i) {
        buff[2 + i] = payload[i];
      }

      this.device.write(buff);
    });
  }

  listAccounts() {
    return new Promise((resolve) => {
      const res = [];

      const onDumpKeys = (buff) => {
        res.push(buff);
      };

      this.on('dump-keys', onDumpKeys);
      this.once('done', () => {
        this.removeListener('dump-keys', onDumpKeys);

        const addresses = [];

        res.forEach((buff) => {
          let i = 0;

          while (i < buff.length) {
            const index = buff[i];
            if (index === 0xFF) {
              return;
            }
            i += 1;

            const address = `0x${buff.slice(i, i + ETH_ADDRESS_SIZE).toString('hex')}`;
            i += ETH_ADDRESS_SIZE;

            addresses.push({
              index,
              address
            });
          }
        });

        resolve(addresses);
      });

      const buff = _.fill(new Array(Key.HID_PACKET_SIZE), 0);
      buff[0] = Key.CMD.DUMP_KEYS;
      this.device.write(buff);
    });
  }

  close() {
    this.device.close();
  }
}

class Wallet {
  static fromHID() {
    const device = Key.fromHID();
    return new Wallet(device);
  }

  constructor(device) {
    this.device = device;
  }

  async init() {
    this.accounts = await this.device.listAccounts();
  }

  deleteAddress() {
    const index = this.getAddressIndex(address);
    return this.device.deleteKey(index);
  }

  getAddresses() {
    return this.accounts.map((account) => account.address);
  }

  getAddressIndex(address) {
    address = address.toLowerCase();
    const account = this.accounts.find((account) => account.address = address);
    if (!account) {
      throw new Error('Account not found');
    }
    return account.index;
  }

  async sign(address, transaction) {
    const index = this.getAddressIndex(address);

    const txHash = ethers.utils.keccak256(ethers.utils.serializeTransaction(transaction));

    const signature = await this.device.sign(index, Buffer.from(txHash.substring(2), 'hex'));

    const r = ethereumjsUtil.setLengthLeft(signature.slice(0, 32), 32);
    let s = signature.slice(32, 64);


    /**
     * EIP-2:
     *  > All transaction signatures whose s-value is greater than
     *  > secp256k1n/2 are now considered invalid.
     */
    let sValue = new BN(s.toString('hex'), 16);
    if (sValue.gt(secp256k1halfN)) {
      sValue = secp256k1N.sub(sValue);
      s = sValue.toBuffer();
    }

    s = ethereumjsUtil.setLengthLeft(s, 32);

    /**
     * As we do not hace the R point's y coordinate we try all
     * the possible values (27, 28) until we recover the right address.
     * https://bitcoin.stackexchange.com/a/38909
     */
    let v = 27;
    let pubKey = ethereumjsUtil.ecrecover(ethereumjsUtil.toBuffer(txHash), v, r, s);
    let addrBuf = ethereumjsUtil.pubToAddress(pubKey);
    let recoveredEthAddr = ethers.utils.getAddress(ethereumjsUtil.bufferToHex(addrBuf));
    if (ethers.utils.getAddress(address) !== recoveredEthAddr) {
      v = 28;

      pubKey = ethereumjsUtil.ecrecover(ethereumjsUtil.toBuffer(txHash), v, r, s);
      addrBuf = ethereumjsUtil.pubToAddress(pubKey);
      recoveredEthAddr = ethers.utils.getAddress(ethereumjsUtil.bufferToHex(addrBuf));
    }

    const rawTransaction = ethers.utils.serializeTransaction(transaction, {
      r: ethereumjsUtil.bufferToHex(r),
      s: ethereumjsUtil.bufferToHex(s),
      v,
    });

    return rawTransaction;
  }

  close() {
    this.device.close();
  }
}

const main = async () => {
  const wallet = Wallet.fromHID();

  await wallet.init();

  const addresses = wallet.getAddresses();
  if (!addresses.length) {
    console.log('no account found');
  }

  console.log(addresses);

  const web3 = new Web3('https://ropsten.infura.io/v3/9e7db74d83f64d2498580acb8a980fe4');

  let nonce = await web3.eth.getTransactionCount(addresses[0]);
  const touchContract = new web3.eth.Contract(Touch.abi, TOUCH_CONTRACT_ADDRESS);
  const encAbi = touchContract.methods.touch().encodeABI();

  const tx = {
    nonce: nonce,
    to: TOUCH_CONTRACT_ADDRESS,
    value: 0,
    chainId: 3,
    gasLimit: 1000000,
    gasPrice: 1000000000,
    data: encAbi,
    chainId: 3
  };

  const sig = await wallet.sign(addresses[0], tx);

  wallet.close();

  web3.eth.sendSignedTransaction(sig)
    .on('transactionHash', (hash) => {
      console.log(`transactionHash = ${hash}`);
    })
    .on('receipt', (receipt) => {
      console.log('receipt', receipt);
    });
};

main();

