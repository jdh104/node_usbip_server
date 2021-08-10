
'use strict';

const ASCII_ENCODED_ZERO = Buffer.from([0]).toString('ASCII');
const DEFAULT_SIMULATED_BUS_NUMBER = 8;
const EMPTY_SETUP_PACKET_BYTES = Buffer.alloc(8);
const USBIP_SERVICE_PORT = 3240;

const net = require('net');
const { EventEmitter } = require('events');
const posix = require('path').posix;
const util = require('util');

const lib = require('./lib.js');

/**
 * @typedef UsbIpServerSimConfig
 * @property {string} version
 * @property {number} [simulatedBusNumber]
 * @property {net.ServerOpts} [tcpOptions]
 * @property {EventEmitterOptions} [eventEmitterOptions]
 * @property {string} [devicesDirectory] Must be an absolute posix path
 */

/**
 * @typedef EventEmitterOptions
 * @property {boolean} [captureRejections]
 */

/**
 * @callback UsbDeviceFindPredicate
 * @param {SimulatedUsbDevice} device
 * @returns {boolean}
 */

/**
 * @typedef UsbIpParsedPacket
 * @property {Error} [error]
 * @property {string} version
 * @property {string} commandCode
 * @property {number} [status]
 * @property {DevListRequestBody
 *          | DevListResponseBody
 *          | ImportRequestBody
 *          | ImportResponseBody
 *          | SubmitCommandBody
 *          | SubmitResponseBody
 *          | UnlinkCommandBody
 *          | UnlinkResponseBody} body type depends on `commandCode`
 */

/**
 * @typedef DevListRequestBody
 * @property {number} status
 */

/**
 * @typedef DevListResponseBody
 * @property {number} status
 * @property {number} deviceListLength
 * @property {SimulatedUsbDeviceConfig[]} deviceList
 */

/**
 * @typedef ImportRequestBody
 * @property {number} status
 * @property {string} busid
 */

/**
 * @typedef ImportResponseBody
 * @property {number} status
 * @property {SimulatedUsbDeviceConfig} device
 */

/**
 * @typedef UsbipBasicHeader
 * @property {string} commandCode
 * @property {number} seqnum
 * @property {number} devid for server, this shall be set to 0
 * @property {number} direction 0: USBIP_DIR_OUT, 1: USBIP_DIR_IN; for server, this shall be 0
 * @property {number} endpoint
 */

/**
 * @typedef SubmitCommandBody
 * @property {UsbipBasicHeader} header
 * @property {number} transferFlags
 * @property {number} transferBufferLength
 * @property {number} startFrame shall be set to 0 if not ISO transfer
 * @property {number} numberOfPackets shall be set to 0xffffffff if not ISO transfer
 * @property {number} interval
 * @property {Buffer} setup
 * @property {Buffer} transferBuffer
 * @property {Buffer} isoPacketDescriptor
 */

/**
 * @typedef SubmitResponseBody
 * @property {UsbipBasicHeader} header
 * @property {number} status
 * @property {number} actualLength
 * @property {number} startFrame
 * @property {number} numberOfPackets
 * @property {number} errorCount
 * @property {Buffer} transferBuffer
 * @property {Buffer} isoPacketDescriptor
 */

/**
 * @typedef UnlinkCommandBody
 * @property {UsbipBasicHeader} header
 * @property {number} unlinkSeqNum
 * */

/**
 * @typedef UnlinkResponseBody
 * @property {UsbipBasicHeader} header
 * @property {number} status
 * */

class UsbIpServerSim extends EventEmitter {
    /**
     * 
     * @param {UsbIpServerSimConfig} config
     */
    constructor(config) {
        super(config.eventEmitterOptions);
        config = config || {};

        try {
            this._server = new UsbIpServer(config.tcpOptions, config.devicesDirectory, config.simulatedBusNumber);
            this._protocolLayer = new UsbIpProtocolLayer(this._server, config.version);

            this._protocolLayer.on('error', error => this.emit('protocolError', error));
            this._protocolLayer.on('write', (socket, data, error) => this.emit('write', socket, data, error));
        } catch (error) {
            throw new Error(`Failed to initialize net.Server object in UsbIpServerSim constructor. Reason = ${error}`);
        }
    }

    /**
     * 
     * @param {SimulatedUsbDevice} device
     */
    exportDevice(device) {
        let emptyIndexes = [...this._server.getEmptyIndexes()];
        if (emptyIndexes.length < 1) {
            var defaultDeviceNumber = this._server.devices.push(device);
        } else {
            var defaultDeviceNumber = emptyIndexes[0];
            this._server.devices[defaultDeviceNumber] = device;
        }

        this._updateDeviceConfiguration(device.config, defaultDeviceNumber);

        return device;
    }

    /**
     * Assign values which were left out by the user.
     * @param {SimulatedUsbDeviceConfig} conf
     * @param {number} defaultDeviceNumber
     */
    _updateDeviceConfiguration(conf, defaultDeviceNumber) {
        if (!conf.busnum) {
            conf.busnum = this._server.busNumber;
        }

        if (!conf.devnum) {
            conf.devnum = defaultDeviceNumber;
        }

        if (!conf.busid) {
            conf.busid = `${conf.busnum}-${conf.devnum}`;
        }

        if (!conf.path) {
            conf.path = posix.join(this._server.devicesDirectory, conf.busid);
        }

        if (!conf.interfaces) {
            conf.interfaces = [];
        }

        if (!conf.bNumInterfaces) {
            conf.bNumInterfaces = conf.interfaces.length;
        }
    }

    /**
     * 
     * @param {number | string | SimulatedUsbDevice} device Can be index, path, busid, or the device object itself
     * @returns {SimulatedUsbDevice}
     */
    removeDevice(device) {
        let devices = this._server.devices;
        if (isNaN(device)) {
            let index = this._server.findDeviceIndex(device);

            if (index == -1) {
                return null;
            } else {
                try {
                    return this.removeDevice(index);
                } catch (err) {
                    throw new Error(`Converted query ${device} to index ${index}; but failed to remove device (THIS IS NOT SUPPOSED TO HAPPEN). Reason = ${util.inspect(err)}`);
                }
            }
        } else if (device >= devices.length || device < 0) {
            throw new Error(`Index '${device}' out of range; numDevices = ${devices.length}`);
        } else {
            let removedDevice = devices[device];
            delete devices[device];

            this._protocolLayer.notifyRemoved(removedDevice);
            return removedDevice;
        }
    }

    *removeAllDevices() {
        for (let removedDevice of this._server.devices.splice(0, Infinity)) {
            this._protocolLayer.notifyRemoved(removedDevice);
            yield removedDevice;
        }
    }

    /**
     *
     * @param {string} address
     * @param {number} [port] Default: 3240
     */
    listen(address, port) {
        this._server.listen(port || USBIP_SERVICE_PORT, address);
        return this;
    }
}

class UsbIpProtocolLayer extends EventEmitter {
    /**
     * @param {UsbIpServer} serverToControl
     * @param {string} [version]
     */
    constructor(serverToControl, version) {
        super();
        this.versionString = version;
        this.encodedVersionNumber = 0;
        if (this.versionString) {
            let versionSplit = this.versionString.split('.');
            if (versionSplit.length > 4) {
                throw new Error(`Bad configuration: 'version' may have a maximum of 4 version numbers`);
            }
            for (let versionNibble of versionSplit.reverse()) {
                versionNibble = Number(versionNibble);
                if (isNaN(versionNibble)) {
                    throw new Error(`Bad configuration: 'version' is not formatted correctly (must be numbers seperated by '.' character)`);
                } else if (versionNibble < 0 || versionNibble > 0xf) {
                    throw new Error(`Bad configuration: 'version' numbers must each fit in a nibble; number '${versionNibble}' is too large/small`);
                } else {
                    this.encodedVersionNumber <<= 4;
                    this.encodedVersionNumber += versionNibble;
                }
            }
        }

        this.server = serverToControl;

        if (this.server) {
            this.server.on('connection', socket => {
                socket.on('data', data => {
                    this.handle(data, socket)
                });
                socket.on('close', () => socket.destroy());
            });
        } else {
            this.emit('warning', 'No UsbIpServer object given to control');
        }
    }

    /**
     * 
     * @param {Buffer} incomingData
     * @param {net.Socket} socket
     */
    handle(incomingData, socket) {
        if (incomingData.length < 4) {
            this.emit('error', new Error(`Commands must be at least 4 bytes in length; called handle(${util.inspect(incomingData)})`));
        } else {
            let incomingVersion = incomingData.readUInt16BE();

            // if no version was given by config, simply mirror the client's version
            let outgoingVersion = this.encodedVersionNumber || incomingVersion;

            if (!incomingVersion) {
                var incomingCommand = incomingData.slice(0, 4);
            } else {
                var incomingCommand = incomingData.slice(2, 4);
            }

            let cmdHandler = this[incomingCommand];

            if (!cmdHandler) {
                this.emit('error', new Error(`Unrecognized command ${incomingCommand}`));
            } else {
                try {
                    cmdHandler.bind(this)(socket, outgoingVersion, incomingData);
                } catch (err) {
                    this.emit('error', new Error(`Unable to process incoming packet ${util.inspect(incomingData)}. Reason = ${err}`));
                }
            }
        }
    }

    /**
     * 
     * @param {SimulatedUsbDevice} device
     */
    notifyRemoved(device) {
        // TODO: Does this cleanly inform the OS that the device was unplugged?
        if (device._attachedSocket) {
            device._attachedSocket.end(() => device._attachedSocket.destroy());
        }
    }

    /**
     * 
     * @param {net.Socket} socket
     * @param {Buffer} data
     */
    notifyAndWriteData(socket, data) {
        return socket.write(data, err => {
            this.emit('write', socket, data, err);
        });
    }

    /**
     * 
     * @param {net.Socket} socket The socket from which this command came
     * @param {number} serverVersion
     * @param {Buffer} packet Incoming command data
     */
    [lib.commands.OP_REQ_DEVLIST](socket, serverVersion, packet) {
        if (packet.length != 8) {
            throw new Error('Length of OP_REQ_DEVLIST packet must be 8');
        } else {
            this.notifyAndWriteData(socket, this.constructDeviceListResponse(serverVersion, [...this.server.enumerateDevices()]));
        }
    }

    /**
     *
     * @param {net.Socket} socket The socket from which this command came
     * @param {number} serverVersion
     * @param {Buffer} packet Incoming command data
     */
    [lib.commands.OP_REQ_IMPORT](socket, serverVersion, packet) {
        if (packet.length != 40) {
            throw new Error('Length of OP_REQ_IMPORT packet must be 40');
        } else {
            let requestedBusId = this.readBusId(packet.slice(8, 40));

            let matchingDevice = this.server.getDeviceByBusId(requestedBusId);

            if (matchingDevice && !matchingDevice._attachedSocket) {
                matchingDevice._attachedSocket = socket;

                this.notifyAndWriteData(socket, this.constructImportResponse(serverVersion, matchingDevice, true));
            } else {
                // TODO: device is already attached; send error response
                this.notifyAndWriteData(socket, this.constructImportResponse(serverVersion, null, false));
            }
        }
    }

    /**
     *
     * @param {net.Socket} socket The socket from which this command came
     * @param {number} serverVersion
     * @param {Buffer} packet Incoming command data
     */
    [lib.commands.USBIP_CMD_SUBMIT](socket, serverVersion, packet) {
        let parsedPacket = this.parsePacket(packet);
        if (parsedPacket.error) {
            throw parsedPacket.error;
        } else {
            /** @type {SubmitCommandBody} */
            let body = parsedPacket.body;

            let targetDevice = this.server.getDeviceByDevId(body.header.devid);

            if (!targetDevice) {
                throw new Error(`Could not find device with devId ${body.header.devid}`);
            } else if (!body.setup.equals(EMPTY_SETUP_PACKET_BYTES)) {
                targetDevice.emit('setup', parsedPacket);
            }
        }
    }

    /**
     *
     * @param {net.Socket} socket The socket from which this command came
     * @param {number} serverVersion
     * @param {Buffer} packet Incoming command data
     */
    [lib.commands.USBIP_CMD_UNLINK](socket, serverVersion, packet) {
        // TODO: implement
        throw new Error(`USBIP_CMD_UNLINK Not Implemented. Packet = ${util.inspect(this.parsePacket(packet), false, Infinity)}`);
    }

    /**
     * 
     * @param {Buffer} packet
     * @returns {UsbIpParsedPacket}
     */
    parsePacket(packet) {
        if (packet.length < 4) {
            throw new Error('Parse failure: length of packet must be at least 4');
        } else {
            let parsedObject = {};

            try {
                parsedObject.version = this.readVersion(packet.slice(0, 2));

                if (parsedObject.version == '0') {
                    delete parsedObject.version;
                    parsedObject.commandCode = this.readCommandCode(packet.slice(0, 4));
                    parsedObject.body = this.readCommandBody(parsedObject.commandCode, packet.slice(4));
                } else {
                    parsedObject.commandCode = this.readOperationCode(packet.slice(2, 4));
                    parsedObject.body = this.readOperationBody(parsedObject.version, parsedObject.commandCode, packet.slice(4));
                }
            } catch (err) {
                parsedObject.error = err;
            }

            return parsedObject;
        }
    }

    /**
     * 
     * @param {number} uint16
     */
    constructUInt16BE(uint16) {
        let buf = Buffer.allocUnsafe(2);
        buf.writeUInt16BE(uint16);
        return buf;
    }

    /**
     * 
     * @param {number} uint32
     */
    constructUInt32BE(uint32) {
        let buf = Buffer.allocUnsafe(4);
        buf.writeUInt32BE(uint32);
        return buf;
    }

    /**
     * 
     * @param {string} str
     */
    constructPaddedStringBuffer(str, desiredLength) {
        if (str.length > desiredLength) {
            throw new Error(`Cannot fit str ${str} into ${desiredLength} bytes`);
        } else {
            return Buffer.from(str.padEnd(desiredLength, ASCII_ENCODED_ZERO));
        }
    }

    /**
     * 
     * @param {Buffer} buf
     */
    readPaddedStringBuffer(buf) {
        for (let i = buf.length - 1; i > -1; i--) {
            if (buf[i]) {
                return buf.toString('ASCII', 0, i + 1);
            }
        }

        // if we exit the above loop, buffer must be all zeros
        return '';
    }

    /**
     * 
     * @param {number} serverVersion
     * @param {SimulatedUsbDevice[]} deviceList
     */
    constructDeviceListResponse(serverVersion, deviceList) {
        let responseBytes = Buffer.concat(
            [
                this.constructOperationHeaderBytes(serverVersion, lib.commands.OP_REP_DEVLIST),
                this.constructDeviceListLength(deviceList.length),
            ]
        );

        for (let device of deviceList) {
            responseBytes = Buffer.concat(
                [
                    responseBytes,
                    this.constructDeviceDescription(device, true),
                ]
            );
        }

        return responseBytes;
    }

    /**
     * 
     * @param {Buffer} deviceList
     */
    readDeviceList(deviceList) {
        let parsedDeviceList = [];

        if (deviceList.length < 1) {
            return parsedDeviceList;
        } else {
            let deviceDescription = this.readDeviceDescription(deviceList.slice(0, 312), false);
            let endIndex = 312 + 4 * deviceDescription.bNumInterfaces;

            deviceDescription.interfaces = [...this.readInterfaceList(deviceList.slice(312, endIndex))];
            parsedDeviceList.push(deviceDescription);

            for (let parsedDeviceDescription of this.readDeviceList(deviceList.slice(endIndex))) {
                parsedDeviceList.push(parsedDeviceDescription);
            }

            return parsedDeviceList;
        }
    }

    /**
     * 
     * @param {Buffer} deviceDescription
     * @param {boolean} [allowEmptyDescription]
     * @returns {SimulatedUsbDeviceConfig}
     */
    readDeviceDescription(deviceDescription, allowEmptyDescription) {
        if (deviceDescription.length == 0 && allowEmptyDescription) {
            return {};
        } else if (deviceDescription.length < 312) {
            throw new Error('device description must be at least 312 bytes long');
        } else {
            return {
                path: this.readPaddedStringBuffer(deviceDescription.slice(0, 256)),
                busid: this.readPaddedStringBuffer(deviceDescription.slice(256, 288)),
                busnum: deviceDescription.readUInt32BE(288),
                devnum: deviceDescription.readUInt32BE(292),
                speed: deviceDescription.readUInt32BE(296),
                idVendor: deviceDescription.readUInt16BE(300),
                idProduct: deviceDescription.readUInt16BE(302),
                bcdDevice: deviceDescription.readUInt16BE(304),
                bDeviceClass: deviceDescription[306],
                bDeviceSubClass: deviceDescription[307],
                bDeviceProtocol: deviceDescription[308],
                bConfigurationValue: deviceDescription[309],
                bNumConfigurations: deviceDescription[310],
                bNumInterfaces: deviceDescription[311],
            };
        }
    }

    /**
     * 
     * @param {number} serverVersion
     * @param {SimulatedUsbDevice} deviceToImport
     * @param {boolean} [importSucceeded]
     */
    constructImportResponse(serverVersion, deviceToImport, importSucceeded) {
        importSucceeded = deviceToImport && importSucceeded;
        let responseBytes = this.constructOperationHeaderBytes(serverVersion, lib.commands.OP_REP_IMPORT, importSucceeded ? 0 : 1);

        if (importSucceeded) {
            responseBytes = Buffer.concat(
                [
                    responseBytes,
                    this.constructDeviceDescription(deviceToImport, false),
                ]
            );
        }

        return responseBytes;
    }

    /**
     * 
     * @param {number} serverVersion
     * @param {Buffer} replyCode
     * @param {number} [status]
     */
    constructOperationHeaderBytes(serverVersion, replyCode, status) {
        return Buffer.concat([
            this.constructVersionBytes(serverVersion),
            replyCode,
            this.constructStatusBytes(status || 0),
        ]);
    }

    /**
     * 
     * @param {number} version
     */
    constructVersionBytes(version) {
        return this.constructUInt16BE(version);
    }

    /**
     * 
     * @param {Buffer} version
     */
    readVersion(version) {
        let versionPieces = [];
        let encodedVersion = version.readUInt16BE();
        while (encodedVersion) {
            versionPieces.push(encodedVersion % 0x10);
            encodedVersion >>= 4;
        }

        if (versionPieces.length == 0) {
            return '0';
        } else {
            return versionPieces.reverse().join('.');
        }
    }

    /**
     * 
     * @param {number} replyCode
     */
    constructReplyCodeBytes(replyCode) {
        return this.constructUInt16BE(replyCode);
    }

    /**
     * 
     * @param {Buffer} opCodeBytes
     */
    readOperationCode(opCodeBytes) {
        for (let operationName in lib.commands) {
            if (opCodeBytes.equals(lib.commands[operationName])) {
                return operationName;
            }
        }

        throw new Error(`Invalid op-code '${opCodeBytes}' (${opCodeBytes.readUInt16BE()}); commands = ${util.inspect(lib.commands)}`);
    }

    /**
     * 
     * @param {Buffer} commandCodeBytes
     */
    readCommandCode(commandCodeBytes) {
        for (let commandName in lib.commands) {
            if (commandCodeBytes.equals(lib.commands[commandName])) {
                return commandName;
            }
        }

        throw new Error(`Invalid command code '${commandCodeBytes}' (${commandCodeBytes.readUInt32BE()}); commands = ${util.inspect(lib.commands)}`);
    }

    /**
     * 
     * @param {string} version
     * @param {string} operation
     * @param {Buffer} body
     */
    readOperationBody(version, operation, body) {
        try {
            let opCode = lib.commands[operation];
            switch (opCode) {
                case lib.commands.OP_REQ_DEVLIST:
                    return this.readReqDevlistBody(body);

                case lib.commands.OP_REP_DEVLIST:
                    return this.readRepDevlistBody(body);

                case lib.commands.OP_REQ_IMPORT:
                    return this.readReqImportBody(body);

                case lib.commands.OP_REP_IMPORT:
                    return this.readRepImportBody(body);

                default:
                    throw new Error(`Unrecognized commandCode: ${opCode}`);
            }
        } catch (err) {
            throw new Error(`Failed to read operation '${operation}' body. Reason = '${err}'`);
        }
    }

    /**
     * 
     * @param {string} command
     * @param {Buffer} body
     */
    readCommandBody(command, body) {
        try {
            let commandCode = lib.commands[command];
            switch (commandCode) {
                case lib.commands.USBIP_CMD_SUBMIT:
                    return this.readCmdSubmitBody(body);

                case lib.commands.USBIP_RET_SUBMIT:
                    return this.readRetSubmitBody(body);

                case lib.commands.USBIP_CMD_UNLINK:
                    return this.readCmdUnlinkBody(body);

                case lib.commands.USBIP_RET_UNLINK:
                    return this.readRetUnlinkBody(body);

                default:
                    throw new Error(`Unrecognized commandCode: ${commandCode}`);
            }
        } catch (err) {
            throw new Error(`Failed to read command '${command}' body. Reason = '${err}'`);
        }
    }

    /**
     * 
     * @param {Buffer} body
     * @returns {DevListRequestBody}
     */
    readReqDevlistBody(body) {
        if (body.length < 4) {
            throw new Error('Devlist request body must be at least 4 bytes long');
        } else {
            return {
                status: body.readUInt32BE(),
            };
        }
    }

    /**
     *
     * @param {Buffer} body
     * @returns {DevListResponseBody}
     */
    readRepDevlistBody(body) {
        if (body.length < 4) {
            throw new Error('Devlist response body must be at least 8 bytes long');
        } else {
            return {
                status: body.readUInt32BE(),
                deviceListLength: this.readDeviceListLength(body.slice(4, 8)),
                deviceList: this.readDeviceList(body.slice(8)),
            };
        }
    }

    /**
     *
     * @param {Buffer} body
     * @returns {ImportRequestBody}
     */
    readReqImportBody(body) {
        if (body.length < 36) {
            throw new Error('Import request body must be at least 36 bytes long');
        } else {
            return {
                status: body.readUInt32BE(),
                busid: this.readPaddedStringBuffer(body.slice(4, 36)),
            };
        }
    }

    /**
     *
     * @param {Buffer} body
     * @returns {ImportResponseBody}
     */
    readRepImportBody(body) {
        if (body.length < 316) {
            throw new Error('Import request body must be at least 316 bytes long');
        } else {
            return {
                status: body.readUInt32BE(),
                device: this.readDeviceDescription(body.slice(4, 316), true),
            };
        }
    }

    /**
     *
     * @param {Buffer} body
     * @returns {SubmitCommandBody}
     */
    readCmdSubmitBody(body) {
        if (body.length < 44) {
            throw new Error('Submit command body must be at least 44 bytes long');
        } else {
            try {
                let tBufferLength = body.readUInt32BE(20);
                let tBufferEndIndex = 44 + tBufferLength;
                return {
                    header: this.readUsbipBasicHeader(body.slice(0, 16)),
                    transferFlags: body.readUInt32BE(16),
                    transferBufferLength: tBufferLength,
                    startFrame: body.readUInt32BE(24),
                    numberOfPackets: body.readUInt32BE(28),
                    interval: body.readUInt32BE(32),
                    setup: body.slice(36, 44),
                    transferBuffer: body.slice(44, tBufferEndIndex),
                    isoPacketDescriptor: body.slice(tBufferEndIndex),
                };
            } catch (err) {
                throw new Error(`Failed to parse submit command body. Reason = ${err}`);
            }
        }
    }

    /**
     *
     * @param {Buffer} body
     * @returns {SubmitResponseBody}
     */
    readRetSubmitBody(body) {
        if (body.length < 44) {
            throw new Error('Submit response body must be at least 44 bytes long');
        } else {
            try {
                let tBufferLength = body.readUInt32BE(20);
                let tBufferEndIndex = 44 + tBufferLength;
                return {
                    header: this.readUsbipBasicHeader(body.slice(0, 16)),
                    status: body.readUInt32BE(16),
                    actualLength: tBufferLength,
                    startFrame: body.readUInt32BE(24),
                    numberOfPackets: body.readUInt32BE(28),
                    errorCount: body.readUInt32BE(32),
                    // paddingThatWeIgnore: body.slice(32, 44),
                    transferBuffer: body.slice(44, tBufferEndIndex),
                    isoPacketDescriptor: body.slice(tBufferEndIndex),
                };
            } catch (err) {
                throw new Error(`Failed to parse submit response body. Reason = ${err}`);
            }
        }
    }

    /**
     *
     * @param {Buffer} body
     * @returns {UnlinkCommandBody}
     */
    readCmdUnlinkBody(body) {
        if (body.length < 44) {
            throw new Error('Unlink command body must be at least 44 bytes long');
        } else {
            try {
                return {
                    header: this.readUsbipBasicHeader(body.slice(0, 16)),
                    unlinkSeqNum: body.readUInt32BE(16),
                    // paddingThatWeIgnore: body.slice(20, 44),
                };
            } catch (err) {
                throw new Error(`Failed to parse unlink command body. Reason = ${err}`);
            }
        }
    }

    /**
     *
     * @param {Buffer} body
     * @returns {UnlinkResponseBody}
     */
    readRetUnlinkBody(body) {
        if (body.length < 44) {
            throw new Error('Unlink response body must be at least 44 bytes long');
        } else {
            try {
                return {
                    header: this.readUsbipBasicHeader(body.slice(0, 16)),
                    status: body.readUInt32BE(16),
                    // paddingThatWeIgnore: body.slice(20, 44),
                };
            } catch (err) {
                throw new Error(`Failed to parse unlink response body. Reason = ${err}`);
            }
        }
    }

    /**
     * // NOTE: that official USBIP documentation includes the 'command' within the packets which
     * // use `usbip_header_basic`, but our parsing logic does not; instead, the `usbip_header_basic`
     * // is 16 bytes long, beginning at the seqnum field. This is because when taking any arbitrary
     * // buffer and deciding what command it represents, there is no way to distinguish between the 
     * // "OP" commands and the "USBIP" commands without extra context.
     * @param {Buffer} header
     * @returns {UsbipBasicHeader}
     */
    readUsbipBasicHeader(header) {
        if (header.length != 16) {
            throw new Error('USBIP basic header must be 16 bytes long');
        } else {
            try {
                return {
                    seqnum: header.readUInt32BE(),
                    devid: header.readUInt32BE(4),
                    direction: header.readUInt32BE(8),
                    endpoint: header.readUInt32BE(12),
                };
            } catch (err) {
                throw new Error(`Failed to parse usbip basic header. Reason = ${err}`);
            }
        }
    }

    /**
     * 
     * @param {number} status
     */
    constructStatusBytes(status) {
        return this.constructUInt32BE(status);
    }

    /**
     * 
     * @param {number} length
     */
    constructDeviceListLength(length) {
        return this.constructUInt32BE(length);
    }

    /**
     * 
     * @param {Buffer} length
     */
    readDeviceListLength(length) {
        return length.readUInt32BE();
    }

    /**
     * 
     * @param {SimulatedUsbDevice} device
     * @param {boolean} [includeInterfaceDescriptions] Default: false
     */
    constructDeviceDescription(device, includeInterfaceDescriptions) {
        let config = device.config;
        let deviceDescriptionBytes = Buffer.concat(
            [
                this.constructPathBytes(config.path),
                this.constructBusId(config.busid),
                this.constructBusNum(config.busnum),
                this.constructDevNum(config.devnum),
                this.constructSpeed(config.speed),
                this.constructVendorId(config.idVendor),
                this.constructProductId(config.idProduct),
                this.constructDeviceBcd(config.bcdDevice),

                // single-byte entries (not really worth helper-methods)
                Buffer.from(
                    [
                        config.bDeviceClass,
                        config.bDeviceSubClass,
                        config.bDeviceProtocol,
                        config.bConfigurationValue,
                        config.bNumConfigurations,
                        config.interfaces.length
                    ]
                ),
            ]
        );

        if (includeInterfaceDescriptions) {
            for (let deviceInterface of config.interfaces) {
                deviceDescriptionBytes = Buffer.concat(
                    [
                        deviceDescriptionBytes,
                        this.constructDeviceInterfaceDescription(deviceInterface),
                    ]
                );
            }
        }

        return deviceDescriptionBytes;
    }

    /**
     * 
     * @param {SimulatedUsbDeviceInterface} deviceInterface
     */
    constructDeviceInterfaceDescription(deviceInterface) {
        let interfaceConfig = deviceInterface.config;

        return Buffer.from(
            [
                interfaceConfig.bInterfaceClass,
                interfaceConfig.bInterfaceSubClass,
                interfaceConfig.bInterfaceProtocol,
                0,  // padding byte for alignment
            ]
        );
    }

    /**
     * 
     * @param {Buffer} interfaceList
     * @returns {Generator<SimulatedUsbDeviceInterfaceConfig, void, unknown>}
     */
    *readInterfaceList(interfaceList) {
        if (interfaceList.length % 4 != 0) {
            throw new Error('Interface list length must be a multiple of 4');
        } else {
            for (let beginIndex = 0; beginIndex < interfaceList.length; beginIndex += 4) {
                let interfaceDescription = interfaceList.slice(beginIndex, beginIndex + 4);

                yield {
                    bInterfaceClass: interfaceDescription[0],
                    bInterfaceSubClass: interfaceDescription[1],
                    bInterfaceProtocol: interfaceDescription[2],
                    paddingByte: interfaceDescription[3],
                };
            }
        }
    }

    /**
     * 
     * @param {string} path
     */
    constructPathBytes(path) {
        return this.constructPaddedStringBuffer(path, 256);
    }

    /**
     *
     * @param {string} path
     */
    constructBusId(busId) {
        return this.constructPaddedStringBuffer(busId, 32);
    }

    /**
     * 
     * @param {Buffer} busId
     */
    readBusId(busId) {
        return this.readPaddedStringBuffer(busId);
    }

    /**
     * 
     * @param {number} busNum
     */
    constructBusNum(busNum) {
        return this.constructUInt32BE(busNum);
    }

    /**
     * 
     * @param {number} devNum
     */
    constructDevNum(devNum) {
        return this.constructUInt32BE(devNum);
    }

    /**
     * 
     * @param {number} speed
     */
    constructSpeed(speed) {
        return this.constructUInt32BE(speed);
    }

    /**
     * 
     * @param {number} idVendor
     */
    constructVendorId(idVendor) {
        return this.constructUInt16BE(idVendor);
    }

    /**
     * 
     * @param {number} idProduct
     */
    constructProductId(idProduct) {
        return this.constructUInt16BE(idProduct);
    }

    /**
     * 
     * @param {number} bcdDevice
     */
    constructDeviceBcd(bcdDevice) {
        return this.constructUInt16BE(bcdDevice);
    }
}

class UsbIpServer extends net.Server {
    /**
     * 
     * @param {net.ServerOpts} tcpOptions
     * @param {string} [devicesDirectory]
     * @param {number} [busNumber]
     */
    constructor(tcpOptions, devicesDirectory, busNumber) {
        busNumber = busNumber || DEFAULT_SIMULATED_BUS_NUMBER;
        devicesDirectory = devicesDirectory || posix.join(posix.sep, 'sys', 'devices');

        if (!posix.isAbsolute(devicesDirectory)) {
            throw new Error(`deviceDirectory must be an absolute posix path; instead got '${devicesDirectory}'`);
        } else {
            devicesDirectory = posix.resolve(devicesDirectory);
        }

        super(tcpOptions || { allowHalfOpen: false, pauseOnConnect: false, });
        this.busNumber = busNumber
        this.devicesDirectory = devicesDirectory;

        /** @type {SimulatedUsbDevice[]} */
        this.devices = [];
    }

    *enumerateDevices() {
        for (let device of this.devices) {
            if (device) {
                yield device;
            }
        }
    }

    *getEmptyIndexes() {
        for (let deviceIndex in this.devices) {
            if (!this.devices[deviceIndex]) {
                yield Number(deviceIndex);
            }
        }
    }

    /**
     * 
     * @param {string | SimulatedUsbDevice} query path, busid, or SimulatedUsbDevice
     * @returns {number} index of device queried, or -1 if no result could be found
     */
    findDeviceIndex(query) {
        if (query == null) {
            return -1;
        } else if (typeof '' == typeof query) {
            let index = this.findDeviceIndex(this.getDeviceByPath(query));

            if (index == -1) {
                return this.findDeviceIndex(this.getDeviceByBusId(query));
            } else {
                return index;
            }
        } else {
            return this.devices.findIndex(device => device == query);
        }
    }

    /**
     * 
     * @param {UsbDeviceFindPredicate} queryFunc
     */
    getDeviceWith(queryFunc) {
        for (let device of this.enumerateDevices()) {
            if (queryFunc(device)) {
                return device;
            }
        }

        return null;
    }

    /**
     * 
     * @param {string} pathQuery
     */
    getDeviceByPath(pathQuery) {
        return this.getDeviceWith(device => device.config.path == pathQuery);
    }

    /**
     * 
     * @param {string} busIdQuery
     */
    getDeviceByBusId(busIdQuery) {
        return this.getDeviceWith(device => device.config.busid == busIdQuery);
    }

    /**
     * 
     * @param {number} devIdQuery
     */
    getDeviceByDevId(devIdQuery) {
        let busNum = deviceId >> 16;
        let devNum = deviceId % 0x10000;

        return this.getDeviceWith(device => device.config.busnum == busNum && device.config.devnum == devNum);
    }
}

/**
 * @typedef SimulatedUsbDeviceConfig
 * @property {string} [path]   Will be automatically set by server simulator when exported (if not present)
 * @property {string} [busid]  Will be automatically set by server simulator when exported (if not present)
 * @property {number} [busnum] Will be automatically set by server simulator when exported (if not present)
 * @property {number} [devnum] Will be automatically set by server simulator when exported (if not present)
 * @property {number} speed
 * @property {number} idVendor
 * @property {number} idProduct
 * @property {number} bcdDevice
 * @property {number} bDeviceClass
 * @property {number} bDeviceSubClass
 * @property {number} bDeviceProtocol
 * @property {number} bConfigurationValue
 * @property {number} bNumConfigurations
 * @property {number} [bNumInterfaces]
 * @property {SimulatedUsbDeviceInterface[]} [interfaces]
 */

/**
 * @typedef SimulatedUsbDeviceInterfaceConfig
 * @property {number} bInterfaceClass
 * @property {number} bInterfaceSubClass
 * @property {number} bInterfaceProtocol
 */

class SimulatedUsbDevice extends EventEmitter {
    /**
     * 
     * @param {SimulatedUsbDeviceConfig} config
     */
    constructor(config) {
        super();
        this.config = config;

        /** @type {net.Socket} */
        this._attachedSocket = null;
    }
}

class SimulatedUsbDeviceInterface {
    /**
     * 
     * @param {SimulatedUsbDeviceInterfaceConfig} config
     */
    constructor(config) {
        this.config = config;
    }
}

module.exports = {
    UsbIpServerSim,
    SimulatedUsbDevice,
    SimulatedUsbDeviceInterface,

    /** not necessary for normal operation */
    usbIpInternals: {
        lib,
        UsbIpProtocolLayer,
        UsbIpServer,
    }
};

if (!module.parent) {
    process.on('uncaughtException', err => {
        console.error(util.inspect(err));
    });

    let server = new UsbIpServerSim({ /*version: '1.1.1'*/ });
    server.on('write', (socket, data, error) => {
        if (error) {
            console.log(`Error writing ${util.inspect(data)}: ${util.inspect(error)}`);
        } else {
            console.log(`Wrote ${util.inspect(data)}`);
        }
    });

    server.on('protocolError', console.error);

    let scannerDevice = new SimulatedUsbDevice({
        //busnum: 3,
        //devnum: 1,
        //path: '/sys/devices/simulation/usb3/3-1',
        //busid: '3-1',
        bcdDevice: 261,
        idVendor: 1008,
        idProduct: 825,
        bDeviceClass: 2,
        bDeviceSubClass: 0,
        bDeviceProtocol: 0,
        bConfigurationValue: 0, // dont have example of this
        bNumConfigurations: 1,
        speed: 3,
        interfaces: [],
        //interfaces: [
        //    new SimulatedUsbDeviceInterface({
        //        bInterfaceClass: 0,    // dont have example of these
        //        bInterfaceSubClass: 0, // dont have example of these
        //        bInterfaceProtocol: 0, // dont have example of these
        //    }),
        //],
    });

    server.exportDevice(scannerDevice);

    server.listen('0.0.0.0');

    let data = {
        "2021-08-09T21:06:49.540Z": [1, 17, 128, 3, 0, 0, 0, 0, 49, 45, 49, 56, 55, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:49.563Z": [1, 17, 0, 3, 0, 0, 0, 0, 92, 92, 63, 92, 117, 115, 98, 35, 118, 105, 100, 95, 52, 49, 51, 99, 38, 112, 105, 100, 95, 51, 48, 49, 97, 35, 53, 38, 50, 97, 100, 51, 53, 56, 98, 54, 38, 48, 38, 49, 49, 35, 123, 102, 98, 50, 54, 53, 50, 54, 55, 45, 99, 54, 48, 57, 45, 52, 49, 101, 54, 45, 56, 101, 99, 97, 45, 97, 50, 48, 100, 57, 50, 97, 56, 51, 51, 101, 54, 125, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 49, 45, 49, 56, 55, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 187, 0, 0, 0, 3, 65, 60, 48, 26, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:49.617Z": [0, 0, 0, 1, 255, 255, 255, 7, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 6, 0, 2, 0, 0, 9, 0],
        "2021-08-09T21:06:49.619Z": [0, 0, 0, 3, 255, 255, 255, 7, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 2, 34, 0, 1, 1, 0, 160, 50],
        "2021-08-09T21:06:49.622Z": [0, 0, 0, 1, 0, 0, 0, 8, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 6, 0, 1, 0, 0, 18, 0],
        "2021-08-09T21:06:49.624Z": [0, 0, 0, 3, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 18, 1, 0, 2, 0, 0, 0, 8, 60, 65, 26, 48, 0, 1, 1, 2, 0, 1],
        "2021-08-09T21:06:49.627Z": [0, 0, 0, 1, 1, 0, 0, 8, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 6, 0, 2, 0, 0, 9, 0],
        "2021-08-09T21:06:49.629Z": [0, 0, 0, 3, 1, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 2, 34, 0, 1, 1, 0, 160, 50],
        "2021-08-09T21:06:49.634Z": [0, 0, 0, 1, 2, 0, 0, 8, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 6, 0, 2, 0, 0, 34, 0],
        "2021-08-09T21:06:49.637Z": [0, 0, 0, 3, 2, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 2, 34, 0, 1, 1, 0, 160, 50, 9, 4, 0, 0, 1, 3, 1, 2, 0, 9, 33, 17, 1, 0, 1, 34, 46, 0, 7, 5, 129, 3, 4, 0, 10],
        "2021-08-09T21:06:49.660Z": [0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 187, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 1, 0, 187, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 11, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:49.664Z": [0, 0, 0, 3, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:49.669Z": [0, 0, 0, 3, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:49.786Z": [0, 0, 0, 1, 0, 0, 0, 3, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 6, 0, 3, 0, 0, 255, 0],
        "2021-08-09T21:06:49.789Z": [0, 0, 0, 3, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 3, 9, 4],
        "2021-08-09T21:06:49.792Z": [0, 0, 0, 1, 0, 0, 0, 4, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 6, 2, 3, 9, 4, 255, 0],
        "2021-08-09T21:06:49.794Z": [0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 58, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 58, 3, 68, 0, 101, 0, 108, 0, 108, 0, 32, 0, 77, 0, 83, 0, 49, 0, 49, 0, 54, 0, 32, 0, 85, 0, 83, 0, 66, 0, 32, 0, 79, 0, 112, 0, 116, 0, 105, 0, 99, 0, 97, 0, 108, 0, 32, 0, 77, 0, 111, 0, 117, 0, 115, 0, 101, 0],
        "2021-08-09T21:06:49.798Z": [0, 0, 0, 1, 0, 0, 0, 5, 0, 1, 0, 187, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 33, 10, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:49.801Z": [0, 0, 0, 3, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:49.806Z": [0, 0, 0, 1, 0, 0, 0, 6, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 110, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 129, 6, 0, 34, 0, 0, 110, 0],
        "2021-08-09T21:06:49.809Z": [0, 0, 0, 3, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 46, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 1, 9, 2, 161, 1, 9, 1, 161, 0, 5, 9, 25, 1, 41, 3, 21, 0, 37, 1, 149, 8, 117, 1, 129, 2, 5, 1, 9, 48, 9, 49, 9, 56, 21, 129, 37, 127, 117, 8, 149, 3, 129, 6, 192, 192],
        "2021-08-09T21:06:49.811Z": [0, 0, 0, 1, 0, 0, 0, 7, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 8, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:49.969Z": [0, 0, 0, 1, 0, 0, 0, 9, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 6, 0, 3, 0, 0, 255, 0],
        "2021-08-09T21:06:49.972Z": [0, 0, 0, 3, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 3, 9, 4],
        "2021-08-09T21:06:49.975Z": [0, 0, 0, 1, 0, 0, 0, 10, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 6, 1, 3, 9, 4, 255, 0],
        "2021-08-09T21:06:49.977Z": [0, 0, 0, 3, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 14, 3, 80, 0, 105, 0, 120, 0, 65, 0, 114, 0, 116, 0],
        "2021-08-09T21:06:49.979Z": [0, 0, 0, 1, 0, 0, 0, 11, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 6, 2, 3, 9, 4, 255, 0],
        "2021-08-09T21:06:49.982Z": [0, 0, 0, 3, 0, 0, 0, 11, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 58, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 58, 3, 68, 0, 101, 0, 108, 0, 108, 0, 32, 0, 77, 0, 83, 0, 49, 0, 49, 0, 54, 0, 32, 0, 85, 0, 83, 0, 66, 0, 32, 0, 79, 0, 112, 0, 116, 0, 105, 0, 99, 0, 97, 0, 108, 0, 32, 0, 77, 0, 111, 0, 117, 0, 115, 0, 101, 0],
        "2021-08-09T21:06:59.368Z": [0, 0, 0, 3, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 254, 0],
        "2021-08-09T21:06:59.371Z": [0, 0, 0, 1, 0, 0, 0, 12, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.374Z": [0, 0, 0, 3, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0],
        "2021-08-09T21:06:59.377Z": [0, 0, 0, 1, 0, 0, 0, 13, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.382Z": [0, 0, 0, 3, 0, 0, 0, 12, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0],
        "2021-08-09T21:06:59.388Z": [0, 0, 0, 1, 0, 0, 0, 14, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.391Z": [0, 0, 0, 3, 0, 0, 0, 13, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 254, 0],
        "2021-08-09T21:06:59.393Z": [0, 0, 0, 1, 0, 0, 0, 15, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.398Z": [0, 0, 0, 3, 0, 0, 0, 14, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0],
        "2021-08-09T21:06:59.403Z": [0, 0, 0, 1, 0, 0, 0, 16, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.406Z": [0, 0, 0, 3, 0, 0, 0, 15, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 254, 0],
        "2021-08-09T21:06:59.408Z": [0, 0, 0, 1, 0, 0, 0, 17, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.414Z": [0, 0, 0, 3, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 254, 0],
        "2021-08-09T21:06:59.419Z": [0, 0, 0, 1, 0, 0, 0, 18, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.422Z": [0, 0, 0, 3, 0, 0, 0, 17, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0],
        "2021-08-09T21:06:59.425Z": [0, 0, 0, 1, 0, 0, 0, 19, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.430Z": [0, 0, 0, 3, 0, 0, 0, 18, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0],
        "2021-08-09T21:06:59.435Z": [0, 0, 0, 1, 0, 0, 0, 20, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.439Z": [0, 0, 0, 3, 0, 0, 0, 19, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0],
        "2021-08-09T21:06:59.441Z": [0, 0, 0, 1, 0, 0, 0, 21, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.446Z": [0, 0, 0, 3, 0, 0, 0, 20, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 254, 0],
        "2021-08-09T21:06:59.449Z": [0, 0, 0, 1, 0, 0, 0, 22, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.462Z": [0, 0, 0, 3, 0, 0, 0, 21, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0],
        "2021-08-09T21:06:59.464Z": [0, 0, 0, 1, 0, 0, 0, 23, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.478Z": [0, 0, 0, 3, 0, 0, 0, 22, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0],
        "2021-08-09T21:06:59.480Z": [0, 0, 0, 1, 0, 0, 0, 24, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.501Z": [0, 0, 0, 3, 0, 0, 0, 23, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0],
        "2021-08-09T21:06:59.503Z": [0, 0, 0, 1, 0, 0, 0, 25, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.526Z": [0, 0, 0, 3, 0, 0, 0, 24, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 253, 0],
        "2021-08-09T21:06:59.528Z": [0, 0, 0, 1, 0, 0, 0, 26, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.534Z": [0, 0, 0, 3, 0, 0, 0, 25, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 255, 0],
        "2021-08-09T21:06:59.535Z": [0, 0, 0, 1, 0, 0, 0, 27, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.542Z": [0, 0, 0, 3, 0, 0, 0, 26, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 255, 0],
        "2021-08-09T21:06:59.544Z": [0, 0, 0, 1, 0, 0, 0, 28, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.550Z": [0, 0, 0, 3, 0, 0, 0, 27, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0],
        "2021-08-09T21:06:59.553Z": [0, 0, 0, 1, 0, 0, 0, 29, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.558Z": [0, 0, 0, 3, 0, 0, 0, 28, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0],
        "2021-08-09T21:06:59.560Z": [0, 0, 0, 1, 0, 0, 0, 30, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.566Z": [0, 0, 0, 3, 0, 0, 0, 29, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 255, 0],
        "2021-08-09T21:06:59.567Z": [0, 0, 0, 1, 0, 0, 0, 31, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.574Z": [0, 0, 0, 3, 0, 0, 0, 30, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0],
        "2021-08-09T21:06:59.575Z": [0, 0, 0, 1, 0, 0, 0, 32, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.582Z": [0, 0, 0, 3, 0, 0, 0, 31, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 254, 0],
        "2021-08-09T21:06:59.583Z": [0, 0, 0, 1, 0, 0, 0, 33, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.589Z": [0, 0, 0, 3, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0],
        "2021-08-09T21:06:59.591Z": [0, 0, 0, 1, 0, 0, 0, 34, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.614Z": [0, 0, 0, 3, 0, 0, 0, 33, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0],
        "2021-08-09T21:06:59.615Z": [0, 0, 0, 1, 0, 0, 0, 35, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.630Z": [0, 0, 0, 3, 0, 0, 0, 34, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0],
        "2021-08-09T21:06:59.631Z": [0, 0, 0, 1, 0, 0, 0, 36, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.638Z": [0, 0, 0, 3, 0, 0, 0, 35, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0],
        "2021-08-09T21:06:59.639Z": [0, 0, 0, 1, 0, 0, 0, 37, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.645Z": [0, 0, 0, 3, 0, 0, 0, 36, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 1, 0],
        "2021-08-09T21:06:59.647Z": [0, 0, 0, 1, 0, 0, 0, 38, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.653Z": [0, 0, 0, 3, 0, 0, 0, 37, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0],
        "2021-08-09T21:06:59.655Z": [0, 0, 0, 1, 0, 0, 0, 39, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.662Z": [0, 0, 0, 3, 0, 0, 0, 38, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 0],
        "2021-08-09T21:06:59.663Z": [0, 0, 0, 1, 0, 0, 0, 40, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.669Z": [0, 0, 0, 3, 0, 0, 0, 39, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 0],
        "2021-08-09T21:06:59.671Z": [0, 0, 0, 1, 0, 0, 0, 41, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.678Z": [0, 0, 0, 3, 0, 0, 0, 40, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 0],
        "2021-08-09T21:06:59.680Z": [0, 0, 0, 1, 0, 0, 0, 42, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.686Z": [0, 0, 0, 3, 0, 0, 0, 41, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 0],
        "2021-08-09T21:06:59.687Z": [0, 0, 0, 1, 0, 0, 0, 43, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.694Z": [0, 0, 0, 3, 0, 0, 0, 42, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0],
        "2021-08-09T21:06:59.695Z": [0, 0, 0, 1, 0, 0, 0, 44, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.701Z": [0, 0, 0, 3, 0, 0, 0, 43, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0],
        "2021-08-09T21:06:59.703Z": [0, 0, 0, 1, 0, 0, 0, 45, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.710Z": [0, 0, 0, 3, 0, 0, 0, 44, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 0],
        "2021-08-09T21:06:59.711Z": [0, 0, 0, 1, 0, 0, 0, 46, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.718Z": [0, 0, 0, 3, 0, 0, 0, 45, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0],
        "2021-08-09T21:06:59.719Z": [0, 0, 0, 1, 0, 0, 0, 47, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.726Z": [0, 0, 0, 3, 0, 0, 0, 46, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 0],
        "2021-08-09T21:06:59.727Z": [0, 0, 0, 1, 0, 0, 0, 48, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.742Z": [0, 0, 0, 3, 0, 0, 0, 47, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0],
        "2021-08-09T21:06:59.744Z": [0, 0, 0, 1, 0, 0, 0, 49, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.750Z": [0, 0, 0, 3, 0, 0, 0, 48, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0],
        "2021-08-09T21:06:59.751Z": [0, 0, 0, 1, 0, 0, 0, 50, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.758Z": [0, 0, 0, 3, 0, 0, 0, 49, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0],
        "2021-08-09T21:06:59.761Z": [0, 0, 0, 1, 0, 0, 0, 51, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.766Z": [0, 0, 0, 3, 0, 0, 0, 50, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0],
        "2021-08-09T21:06:59.767Z": [0, 0, 0, 1, 0, 0, 0, 52, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.774Z": [0, 0, 0, 3, 0, 0, 0, 51, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0],
        "2021-08-09T21:06:59.777Z": [0, 0, 0, 1, 0, 0, 0, 53, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.782Z": [0, 0, 0, 3, 0, 0, 0, 52, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0],
        "2021-08-09T21:06:59.783Z": [0, 0, 0, 1, 0, 0, 0, 54, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.806Z": [0, 0, 0, 3, 0, 0, 0, 53, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0],
        "2021-08-09T21:06:59.808Z": [0, 0, 0, 1, 0, 0, 0, 55, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.814Z": [0, 0, 0, 3, 0, 0, 0, 54, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0],
        "2021-08-09T21:06:59.815Z": [0, 0, 0, 1, 0, 0, 0, 56, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.823Z": [0, 0, 0, 3, 0, 0, 0, 55, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0],
        "2021-08-09T21:06:59.825Z": [0, 0, 0, 1, 0, 0, 0, 57, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.830Z": [0, 0, 0, 3, 0, 0, 0, 56, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 254, 2, 0],
        "2021-08-09T21:06:59.831Z": [0, 0, 0, 1, 0, 0, 0, 58, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.839Z": [0, 0, 0, 3, 0, 0, 0, 57, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 1, 0],
        "2021-08-09T21:06:59.841Z": [0, 0, 0, 1, 0, 0, 0, 59, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.854Z": [0, 0, 0, 3, 0, 0, 0, 58, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 2, 0],
        "2021-08-09T21:06:59.856Z": [0, 0, 0, 1, 0, 0, 0, 60, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.878Z": [0, 0, 0, 3, 0, 0, 0, 59, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 1, 0],
        "2021-08-09T21:06:59.879Z": [0, 0, 0, 1, 0, 0, 0, 61, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.886Z": [0, 0, 0, 3, 0, 0, 0, 60, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0],
        "2021-08-09T21:06:59.888Z": [0, 0, 0, 1, 0, 0, 0, 62, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.893Z": [0, 0, 0, 3, 0, 0, 0, 61, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0],
        "2021-08-09T21:06:59.895Z": [0, 0, 0, 1, 0, 0, 0, 63, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.902Z": [0, 0, 0, 3, 0, 0, 0, 62, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 254, 0, 0],
        "2021-08-09T21:06:59.904Z": [0, 0, 0, 1, 0, 0, 0, 64, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.910Z": [0, 0, 0, 3, 0, 0, 0, 63, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 254, 0, 0],
        "2021-08-09T21:06:59.911Z": [0, 0, 0, 1, 0, 0, 0, 65, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.917Z": [0, 0, 0, 3, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 254, 0, 0],
        "2021-08-09T21:06:59.919Z": [0, 0, 0, 1, 0, 0, 0, 66, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.926Z": [0, 0, 0, 3, 0, 0, 0, 65, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0],
        "2021-08-09T21:06:59.927Z": [0, 0, 0, 1, 0, 0, 0, 67, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.933Z": [0, 0, 0, 3, 0, 0, 0, 66, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 253, 0, 0],
        "2021-08-09T21:06:59.935Z": [0, 0, 0, 1, 0, 0, 0, 68, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.942Z": [0, 0, 0, 3, 0, 0, 0, 67, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0],
        "2021-08-09T21:06:59.943Z": [0, 0, 0, 1, 0, 0, 0, 69, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.949Z": [0, 0, 0, 3, 0, 0, 0, 68, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0],
        "2021-08-09T21:06:59.951Z": [0, 0, 0, 1, 0, 0, 0, 70, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.966Z": [0, 0, 0, 3, 0, 0, 0, 69, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 254, 0, 0],
        "2021-08-09T21:06:59.968Z": [0, 0, 0, 1, 0, 0, 0, 71, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.974Z": [0, 0, 0, 3, 0, 0, 0, 70, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 254, 255, 0],
        "2021-08-09T21:06:59.975Z": [0, 0, 0, 1, 0, 0, 0, 72, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.982Z": [0, 0, 0, 3, 0, 0, 0, 71, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0],
        "2021-08-09T21:06:59.983Z": [0, 0, 0, 1, 0, 0, 0, 73, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.990Z": [0, 0, 0, 3, 0, 0, 0, 72, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0],
        "2021-08-09T21:06:59.991Z": [0, 0, 0, 1, 0, 0, 0, 74, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:06:59.997Z": [0, 0, 0, 3, 0, 0, 0, 73, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 254, 255, 0],
        "2021-08-09T21:06:59.999Z": [0, 0, 0, 1, 0, 0, 0, 75, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:07:00.014Z": [0, 0, 0, 3, 0, 0, 0, 74, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 254, 255, 0],
        "2021-08-09T21:07:00.015Z": [0, 0, 0, 1, 0, 0, 0, 76, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:07:00.022Z": [0, 0, 0, 3, 0, 0, 0, 75, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 254, 0],
        "2021-08-09T21:07:00.023Z": [0, 0, 0, 1, 0, 0, 0, 77, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:07:00.030Z": [0, 0, 0, 3, 0, 0, 0, 76, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 254, 255, 0],
        "2021-08-09T21:07:00.031Z": [0, 0, 0, 1, 0, 0, 0, 78, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:07:00.053Z": [0, 0, 0, 3, 0, 0, 0, 77, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0],
        "2021-08-09T21:07:00.055Z": [0, 0, 0, 1, 0, 0, 0, 79, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:07:00.069Z": [0, 0, 0, 3, 0, 0, 0, 78, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 254, 0],
        "2021-08-09T21:07:00.071Z": [0, 0, 0, 1, 0, 0, 0, 80, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:07:02.342Z": [0, 0, 0, 3, 0, 0, 0, 79, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0],
        "2021-08-09T21:07:02.344Z": [0, 0, 0, 1, 0, 0, 0, 81, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:07:08.542Z": [0, 0, 0, 3, 0, 0, 0, 80, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0],
        "2021-08-09T21:07:08.544Z": [0, 0, 0, 1, 0, 0, 0, 82, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:07:08.549Z": [0, 0, 0, 3, 0, 0, 0, 81, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 3, 0],
        "2021-08-09T21:07:08.551Z": [0, 0, 0, 1, 0, 0, 0, 83, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:07:08.556Z": [0, 0, 0, 3, 0, 0, 0, 82, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 253, 6, 0],
        "2021-08-09T21:07:08.559Z": [0, 0, 0, 1, 0, 0, 0, 84, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:07:08.564Z": [0, 0, 0, 3, 0, 0, 0, 83, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 249, 9, 0],
        "2021-08-09T21:07:08.566Z": [0, 0, 0, 1, 0, 0, 0, 85, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:07:08.572Z": [0, 0, 0, 3, 0, 0, 0, 84, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 14, 0],
        "2021-08-09T21:07:08.578Z": [0, 0, 0, 1, 0, 0, 0, 86, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:07:08.580Z": [0, 0, 0, 3, 0, 0, 0, 85, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 249, 242, 0],
        "2021-08-09T21:07:08.583Z": [0, 0, 0, 1, 0, 0, 0, 87, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:07:08.588Z": [0, 0, 0, 3, 0, 0, 0, 86, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 172, 248, 0],
        "2021-08-09T21:07:08.593Z": [0, 0, 0, 1, 0, 0, 0, 88, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:07:08.596Z": [0, 0, 0, 3, 0, 0, 0, 87, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 165, 254, 0],
        "2021-08-09T21:07:08.599Z": [0, 0, 0, 1, 0, 0, 0, 89, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:07:08.604Z": [0, 0, 0, 3, 0, 0, 0, 88, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 180, 254, 0],
        "2021-08-09T21:07:08.607Z": [0, 0, 0, 1, 0, 0, 0, 90, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:07:08.611Z": [0, 0, 0, 3, 0, 0, 0, 89, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 181, 5, 0],
        "2021-08-09T21:07:08.613Z": [0, 0, 0, 1, 0, 0, 0, 91, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:07:08.619Z": [0, 0, 0, 3, 0, 0, 0, 90, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 189, 3, 0],
        "2021-08-09T21:07:08.621Z": [0, 0, 0, 1, 0, 0, 0, 92, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:07:08.627Z": [0, 0, 0, 3, 0, 0, 0, 91, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 196, 3, 0],
        "2021-08-09T21:07:08.629Z": [0, 0, 0, 1, 0, 0, 0, 93, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:07:08.635Z": [0, 0, 0, 3, 0, 0, 0, 92, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 208, 3, 0],
        "2021-08-09T21:07:08.638Z": [0, 0, 0, 1, 0, 0, 0, 94, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:07:08.643Z": [0, 0, 0, 3, 0, 0, 0, 93, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 209, 3, 0],
        "2021-08-09T21:07:08.645Z": [0, 0, 0, 1, 0, 0, 0, 95, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:07:08.651Z": [0, 0, 0, 3, 0, 0, 0, 94, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 230, 1, 0],
        "2021-08-09T21:07:08.654Z": [0, 0, 0, 1, 0, 0, 0, 96, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:07:08.675Z": [0, 0, 0, 3, 0, 0, 0, 95, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 251, 0, 0],
        "2021-08-09T21:07:08.677Z": [0, 0, 0, 1, 0, 0, 0, 97, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:07:08.683Z": [0, 0, 0, 3, 0, 0, 0, 96, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0],
        "2021-08-09T21:07:08.686Z": [0, 0, 0, 1, 0, 0, 0, 98, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:07:08.691Z": [0, 0, 0, 3, 0, 0, 0, 97, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 247, 0, 0],
        "2021-08-09T21:07:08.693Z": [0, 0, 0, 1, 0, 0, 0, 99, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:07:08.701Z": [0, 0, 0, 3, 0, 0, 0, 98, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252, 0, 0],
        "2021-08-09T21:07:08.702Z": [0, 0, 0, 1, 0, 0, 0, 100, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:07:11.206Z": [0, 0, 0, 3, 0, 0, 0, 99, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0],
        "2021-08-09T21:07:11.208Z": [0, 0, 0, 1, 0, 0, 0, 101, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:07:15.334Z": [0, 0, 0, 3, 0, 0, 0, 100, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0],
        "2021-08-09T21:07:15.336Z": [0, 0, 0, 1, 0, 0, 0, 102, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:07:17.798Z": [0, 0, 0, 3, 0, 0, 0, 101, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:07:17.800Z": [0, 0, 0, 1, 0, 0, 0, 103, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:07:17.804Z": [0, 0, 0, 3, 0, 0, 0, 102, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 255, 0],
        "2021-08-09T21:07:17.807Z": [0, 0, 0, 1, 0, 0, 0, 104, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:07:17.812Z": [0, 0, 0, 3, 0, 0, 0, 103, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0],
        "2021-08-09T21:07:17.815Z": [0, 0, 0, 1, 0, 0, 0, 105, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
        "2021-08-09T21:07:17.820Z": [0, 0, 0, 3, 0, 0, 0, 104, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 255, 0],
        "2021-08-09T21:07:17.823Z": [0, 0, 0, 1, 0, 0, 0, 106, 0, 1, 0, 187, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
    };

    let fs = require('fs');
    let proto = new UsbIpProtocolLayer();

    for (let key in data) {
        fs.appendFileSync('test.txt', `${key} ${util.inspect(proto.parsePacket(Buffer.from(data[key])), false, Infinity)}`);
        fs.appendFileSync('test.txt', '-----------------------------------------------------------------------------------------------------------------------------------------------------------\r\n');
    }
}
