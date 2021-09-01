
'use strict';

const ASCII_ENCODED_ZERO = Buffer.from([0]).toString('ASCII');
const DEFAULT_SIMULATED_BUS_NUMBER = 8;
const ENGLISH = 0x0409;
const EMPTY_BUFFER = Buffer.alloc(0);
const EMPTY_SETUP_PACKET_BYTES = Buffer.alloc(8);
const UNICODE = 'utf16le';
const USBIP_SERVICE_PORT = 3240;

const net = require('net');
const { EventEmitter } = require('events');
const posix = require('path').posix;
const util = require('util');

const lib = require('./lib.js');
const { Queue } = require('./queue.js');

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
 * @property {SimulatedUsbDeviceSpec[]} deviceList
 */

/**
 * @typedef ImportRequestBody
 * @property {number} status
 * @property {string} busid
 */

/**
 * @typedef ImportResponseBody
 * @property {number} status
 * @property {SimulatedUsbDeviceSpec} device
 */

/**
 * @typedef UsbipBasicHeader
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
 * @property {Buffer | ParsedSetupBytes} setup
 * @property {Buffer} transferBuffer
 * @property {Buffer} isoPacketDescriptor
 * @property {Buffer | UsbIpParsedPacket} [leftoverData]
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
 */

/**
 * @typedef UnlinkResponseBody
 * @property {UsbipBasicHeader} header
 * @property {number} status
 */

/**
 * @typedef ParsedSetupBytes
 * @property {BmRequestType} bmRequestType
 * @property {number} bRequest
 * @property {number} wValue
 * @property {number} wIndex
 * @property {number} wLength
 */

/**
 * @typedef BmRequestType
 * @property {number} direction
 * @property {number} rType
 * @property {number} recipient
 */

/** */
class UsbIpServerSim extends EventEmitter {
    /**
     * @event UsbIpServerSim#protocolError
     * @type {object}
     * @property {Error} err
     */

    /**
     * @event UsbIpServerSim#write
     * @type {object}
     * @property {net.Socket} socket
     * @property {Buffer} data
     * @property {Error} [err]
     */

    /**
     * 
     * @param {UsbIpServerSimConfig} config
     */
    constructor(config) {
        config = config || {};
        super(config.eventEmitterOptions);

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
            var deviceIndex = this._server.devices.push(device) - 1;
        } else {
            var deviceIndex = emptyIndexes[0];
            this._server.devices[deviceIndex] = device;
        }

        try {
            this._normalizeDeviceSpec(device.spec, deviceIndex + 1);
        } catch (err) {
            delete this._server.devices[deviceIndex];
            throw new Error(`Failed to normalize given device's specification. Reason = ${util.inspect(err)}`);
        }

        return device;
    }

    /**
     * Ensure required properties exist, and assign values which were left out by the user.
     * @param {SimulatedUsbDeviceSpec} spec
     * @param {number} defaultDeviceNumber
     */
    _normalizeDeviceSpec(spec, defaultDeviceNumber) {
        for (let requiredPropertyName of [
            'speed',
            'idVendor',
            'idProduct',
            'bcdDevice',
            'bcdUSB',
            'bDeviceClass',
            'bDeviceSubClass',
            'bDeviceProtocol',
            'bMaxPacketSize0',
        ]) {
            if (spec[requiredPropertyName] == null) {
                throw new Error(`SimulatedUsbDeviceSpec requires a value for property name '${requiredPropertyName}'`);
            }
        }

        if (!spec.busnum) {
            spec.busnum = this._server.busNumber;
        }

        if (!spec.devnum) {
            spec.devnum = defaultDeviceNumber;
        }

        if (!spec.busid) {
            spec.busid = `${spec.busnum}-${spec.devnum}`;
        }

        if (!spec.path) {
            // TODO: version formatted as 'something.major.minor.revision'?
            let usbSpecMajorVersion = (spec.bcdUSB || '0.0.0').split('.').slice(-3, -2)[0] || '0';
            spec.path = posix.join(this._server.devicesDirectory, `usb${usbSpecMajorVersion}`, spec.busid);
        }

        if (spec.iManufacturer == null) spec.iManufacturer = 0;
        if (spec.iProduct == null) spec.iProduct = 0;
        if (spec.iSerialNumber == null) spec.iSerialNumber = 0;

        if (!spec.configurations) {
            spec.configurations = [];
        } else {
            for (let configKey in spec.configurations) {
                this._normalizeDeviceConfig(spec.configurations[configKey], Number(configKey) + 1, spec);
            }
        }

        if (spec.bNumConfigurations == null) {
            spec.bNumConfigurations = spec.configurations.length;
        }

        if (spec.configurations.length < 1) {
            throw new Error('Specification must contain at least one configuration object');
        }

        if (!spec.stringDescriptors) {
            spec.stringDescriptors = [];
        }

        if (!spec.supportedLangs) {
            spec.supportedLangs = [ENGLISH];
        } else if (Object.getPrototypeOf(spec.supportedLangs) != Array.prototype) {
            throw new Error(`'supportedLangs' must be of type: Array`);
        }

        if (!spec.bConfigurationValue) spec.bConfigurationValue = 0;
    }

    /**
     * Ensure required properties exist, and assign values which were left out by the user.
     * @param {SimulatedUsbDeviceConfiguration} config
     * @param {number} defaultConfigNumber
     * @param {SimulatedUsbDeviceSpec} parentSpec
     */
    _normalizeDeviceConfig(config, defaultConfigNumber, parentSpec) {
        for (let requiredPropertyName of [
            'bmAttributes',
            'bMaxPower',
        ]) {
            if (config[requiredPropertyName] == null) {
                throw new Error(`SimulatedUsbDeviceConfiguration requires a value for property name '${requiredPropertyName}'`);
            }
        }

        for (let requiredPropertyName of [
            'selfPowered',
            'remoteWakeup',
        ]) {
            if (config.bmAttributes[requiredPropertyName] == null) {
                throw new Error(`SimulatedUsbDeviceConfiguration.bmAttributes requires a value for property name '${requiredPropertyName}'`);
            }
        }

        if (config.bConfigurationValue == null) {
            config.bConfigurationValue = defaultConfigNumber;
        }

        if (!config.interfaces) {
            config.interfaces = [];
        } else {
            for (let interfaceKey in config.interfaces) {
                this._normalizeDeviceInterface(config.interfaces[interfaceKey], Number(interfaceKey) + 1, config, parentSpec);
            }
        }

        if (config._bInterfaceNumber == null) {
            if (config.interfaces.length < 1) {
                config._bInterfaceNumber = 0;
            } else {
                config._bInterfaceNumber = config.interfaces.find(iface => !!iface).bInterfaceNumber;
            }
        }

        if (!config.bNumInterfaces) {
            config.bNumInterfaces = config.interfaces.length;
        }

        if (config.iConfiguration == null) config.iConfiguration = 0;
    }

    /**
     * Ensure required properties exist, and assign values which were left out by the user.
     * @param {SimulatedUsbDeviceInterface} iface
     * @param {number} defaultIfaceNumber
     * @param {SimulatedUsbDeviceConfiguration} parentConfig
     * @param {SimulatedUsbDeviceSpec} parentSpec
     */
    _normalizeDeviceInterface(iface, defaultIfaceNumber, parentConfig, parentSpec) {
        for (let requiredPropertyName of [
            'bInterfaceClass',
            'bInterfaceSubClass',
            'bInterfaceProtocol',
        ]) {
            if (iface[requiredPropertyName] == null) {
                throw new Error(`SimulatedUsbDeviceInterface requires a value for property name '${requiredPropertyName}'`);
            }
        }

        if (!iface.communicationsDescriptors) {
            if (iface.bInterfaceClass == lib.interfaceClasses.communicationsAndCdcControl) {
                throw new Error(`Device interface '${iface.bInterfaceNumber}' with { bInterfaceClass = ${iface.bInterfaceClass} (CDC) } requires 'communicationsDescriptors'`);
            } else {
                iface.communicationsDescriptors = [];
            }
        } else {
            for (let descriptor of iface.communicationsDescriptors) {
                if (!Buffer.isBuffer(descriptor)) {
                    throw new Error(`Device interface '${iface.bInterfaceNumber}' with { bInterfaceClass = ${iface.bInterfaceClass} (CDC) } has 'communicationsDescriptors' array, but contained items must ALL be of type: Buffer`);
                }
            }
        }

        if (iface.bInterfaceClass == lib.interfaceClasses.hid) {
            if (!iface.hidDescriptor) {
                throw new Error(`Device interface '${iface.bInterfaceNumber}' with { bInterfaceClass = ${iface.bInterfaceClass} (HID) } requires 'hidDescriptor'`);
            } else if (!iface.hidDescriptor.preCompiledReport && !iface.hidDescriptor.report) {
                throw new Error(`'hidDescriptor' of interface '${iface.bInterfaceNumber}' must have either an HID Report Descriptor at property 'report', or a Buffer at property 'preCompiledReport'`);
            } else if (!iface.hidDescriptor.preCompiledReport && iface.hidDescriptor.report) {
                throw new Error(`'hidDescriptor' of interface '${iface.bInterfaceNumber}' has unsupported 'report' property ('preCompiledReport' must be used instead)`);
            } else if (!Buffer.isBuffer(iface.hidDescriptor.preCompiledReport)) {
                throw new Error(`'hidDescriptor' of interface '${iface.bInterfaceNumber}' must have 'preCompiledReport' property with type: Buffer`);
            }
        }

        if (iface.hidDescriptor && iface.hidDescriptor.preCompiledReport && iface.hidDescriptor.wDescriptorLength == null) {
            iface.hidDescriptor.wDescriptorLength = iface.hidDescriptor.preCompiledReport.length;
        }

        if (iface.bInterfaceNumber == null) {
            iface.bInterfaceNumber = defaultIfaceNumber;
        }

        if (!iface.endpoints) {
            iface.endpoints = [];
        } else {
            for (let endpointKey in iface.endpoints) {
                this._normalizeDeviceEndpoint(iface.endpoints[endpointKey], Number(endpointKey) + 1, iface, parentConfig, parentSpec);
            }
        }

        if (!iface.bNumEndpoints) {
            iface.bNumEndpoints = iface.endpoints.length;
        }

        if (typeof iface.bAlternateSetting != typeof 0) iface.bAlternateSetting = 0;
        if (typeof iface.iInterface != typeof 0) iface.iInterface = 0;
        if (typeof iface._isIdle != typeof false) iface._isIdle = false;
    }

    /**
     * Ensure required properties exist, and assign values which were left out by the user.
     * @param {SimulatedUsbDeviceEndpoint} endpoint
     * @param {number} defaultEndpointNumber
     * @param {SimulatedUsbDeviceInterface} parentInterface
     * @param {SimulatedUsbDeviceConfiguration} parentConfig
     * @param {SimulatedUsbDeviceSpec} parentSpec
     */
    _normalizeDeviceEndpoint(endpoint, defaultEndpointNumber, parentInterface, parentConfig, parentSpec) {
        for (let requiredPropertyName of [
            'bEndpointAddress',
            'bmAttributes',
            'wMaxPacketSize',
            'bInterval',
        ]) {
            if (endpoint[requiredPropertyName] == null) {
                throw new Error(`SimulatedUsbDeviceEndpoint requires a value for property name '${requiredPropertyName}'`);
            }
        }

        for (let requiredIsoPropertyName of [
            'synchronisationType',
            'usageType',
        ]) {
            if (endpoint.bmAttributes[requiredIsoPropertyName] == null) {
                if (endpoint.bmAttributes.transferType != lib.transferTypes.isochronous) {
                    endpoint.bmAttributes[requiredIsoPropertyName] = 0;
                } else {
                    throw new Error(`SimulatedUsbDeviceEndpoint.bmAttributes requires a value for property name '${requiredIsoPropertyName}' because 'bmAttributes.transferType' is ${endpoint.bmAttributes.transferType} (isochronous)`);
                }
            }
        }

        if (endpoint.bmAttributes.transferType == null) {
            throw new Error(`SimulatedUsbDeviceEndpoint.bmAttributes requires a value for property name 'transferType'`);
        }

        if (!(endpoint.bEndpointAddress.direction === 0 || endpoint.bEndpointAddress.direction === 1)) {
            throw new Error(`SimulatedUsbDeviceEndpoint.bEndpointAddress.direction must be '0' or '1'`);
        }

        if (!endpoint.bEndpointAddress.endpointNumber) endpoint.bEndpointAddress.endpointNumber = defaultEndpointNumber;

        if (parentSpec) {
            if (!parentSpec.endpointShortcutMap || Object.getPrototypeOf(parentSpec.endpointShortcutMap) != Array.prototype) {
                parentSpec.endpointShortcutMap = [];
            }

            parentSpec.endpointShortcutMap[endpoint.bEndpointAddress.endpointNumber] = endpoint;
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

    removeAllDevices() {
        let result = [];

        for (let removedDevice of this._server.devices.splice(0, Infinity)) {
            this._protocolLayer.notifyRemoved(removedDevice);
            result.push(removedDevice);
        }

        return result;
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

/** */
class UsbIpProtocolLayer extends EventEmitter {
    /**
     * @event UsbIpProtocolLayer#warning
     * @type {object}
     * @property {string} message
     */
    
    /**
     * @event UsbIpProtocolLayer#error
     * @type {object}
     * @property {Error} err
     */

    /**
     * @event UsbIpProtocolLayer#socketError
     * @type {object}
     * @property {net.Socket} socket
     * @property {Error} err
     */
        
    /**
     * @event UsbIpProtocolLayer#write
     * @type {object}
     * @property {net.Socket} socket
     * @property {Buffer} data
     * @property {Error} [err]
     */
            
    /**
     * @param {UsbIpServer} serverToControl
     * @param {string} [version]
     * @fires UsbIpProtocolLayer#warning fired if `serverToControl` is not set
     */
    constructor(serverToControl, version) {
        super();
        this.versionString = version;
        if (!version) {
            this.encodedVersionNumber = 0;
        } else {
            this.encodedVersionNumber = this.encodeVersion(version);
        }

        this.server = serverToControl;

        if (this.server) {
            this.server.on('connection', socket => {
                socket.on('data', data => {
                    this.handle(data, socket)
                });
                socket.on('error', err => this.emit('socketError', socket, err));
                socket.on('close', () => socket.destroy());
            });
        } else {
            this.emit('warning', 'No UsbIpServer object given to control');
        }
    }

    /**
     * 
     * @param {Error} err
     * @fires UsbIpProtocolLayer#error
     */
    error(err) {
        this.emit('error', err);
    }

    /**
     * 
     * @param {Buffer} incomingData
     * @param {net.Socket} socket
     */
    handle(incomingData, socket) {
        if (incomingData.length < 4) {
            this.error(new Error(`Commands must be at least 4 bytes in length; called handle(${util.inspect(incomingData)})`));
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
                this.error(new Error(`Unrecognized command ${incomingCommand}`));
            } else {
                try {
                    cmdHandler.bind(this)(socket, outgoingVersion, incomingData);
                } catch (err) {
                    this.error(new Error(`Unable to process incoming packet ${util.inspect(incomingData)}. Reason = ${util.inspect(err)}`));
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
     * @fires UsbIpProtocolLayer#write
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
                this.notifyAndWriteData(socket, this.constructImportResponse(serverVersion, matchingDevice, true));

                matchingDevice._attachedSocket = socket;
                matchingDevice.on('bulkToHost', (bulkRequest, data) => this.handleDeviceBulkData(matchingDevice, bulkRequest, data));
                matchingDevice.on('interrupt', (interrupt, data) => this.handleDeviceInterrupt(matchingDevice, interrupt, data));
                matchingDevice._piops = new Queue(); // this handles any interruptOuts that are leftover if the device was detached then re-attached
                matchingDevice._pbops = new Queue(); // this handles any bulkOuts that are leftover if the device was detached then re-attached
                matchingDevice.emit('attached');
                matchingDevice._attachedSocket.on('close', hadError => {
                    matchingDevice._piips = new Queue(); // unregister pending interruptIns
                    matchingDevice._pbips = new Queue(); // unregister pending bulkIns
                    matchingDevice._attachedSocket = null;
                    matchingDevice.emit('detached');
                });
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
            } else {
                try {
                    // endpoint zero implies transferType = CONTROL
                    let transferType = lib.transferTypes.control;

                    if (body.header.endpoint) {
                        let endpoint = targetDevice._findEndpoint(null, body.header.endpoint);
                        transferType = endpoint.bmAttributes.transferType;
                    }

                    switch (transferType) {
                        case lib.transferTypes.control:
                            this.notifyAndWriteData(socket, this.constructControlPacketResponse(targetDevice, body));
                            break;

                        case lib.transferTypes.isochronous:
                            throw new Error('isochronous transferType Not Implemented');
                            break;

                        case lib.transferTypes.bulk:
                            this.handleBulkPacketBody(targetDevice, body);
                            break;

                        case lib.transferTypes.interrupt:
                            this.handleInterruptPacketBody(targetDevice, body);
                            break;

                        default:
                            throw new Error(`Unrecognized endpoint; known endpoints = ${util.inspect(lib.transferTypes)}`);
                    }
                } catch (err) {
                    this.error(new Error(`Unable to handle submit command to endpoint '${body.header.endpoint}'. Reason = ${util.inspect(err)}`));
                }
            }

            if (body.leftoverData) {
                this.handle(body.leftoverData, socket);
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
        throw new Error(`USBIP_CMD_UNLINK Not Implemented. Packet = ${util.inspect(this.parsePacket(packet, { parseLeftoverData: true, parseSetupPackets: true }), false, Infinity)}`);
    }

    /**
     * 
     * @param {SubmitResponseBody} packet
     */
    constructSubmitResponsePacket(packet) {
        let buf = Buffer.concat(
            [
                lib.commands.USBIP_RET_SUBMIT,
                this.constructUsbipBasicHeader(packet.header.seqnum, packet.header.devid, packet.header.direction, packet.header.endpoint),

                Buffer.from(
                    [
                        0, 0, 0, 0, // status          (4-bytes; to be written later)
                        0, 0, 0, 0, // actualLength    (4-bytes; to be written later)
                        0, 0, 0, 0, // startFrame      (4-bytes; to be written later)
                        0, 0, 0, 0, // numberOfPackets (4-bytes; to be written later)
                        0, 0, 0, 0, // errorCount      (4-bytes; to be written later)
                        0, 0, 0, 0, // padding
                        0, 0, 0, 0, // padding
                    ]
                ),
                
                packet.transferBuffer,
                packet.isoPacketDescriptor,
            ]
        );

        buf.writeUInt32BE(packet.status, 20);
        buf.writeUInt32BE(packet.actualLength, 24);
        buf.writeUInt32BE(packet.startFrame, 28);
        buf.writeUInt32BE(packet.numberOfPackets, 32);
        buf.writeUInt32BE(packet.errorCount, 36);

        return buf;
    }

    /**
     * 
     * @param {SimulatedUsbDevice} targetDevice
     * @param {SubmitCommandBody} body
     */
    constructControlPacketResponse(targetDevice, body) {
        try {
            var transferBuffer = this.handleControlPacketBody(targetDevice, body);
            var isError = false;
        } catch (err) {
            this.emit('error', err);
            var transferBuffer = EMPTY_BUFFER;
            var isError = true;
        }
        
        return this.constructSubmitResponsePacket({
            header: {
                seqnum: body.header.seqnum,
                devid: 0,
                direction: body.header.direction,
                endpoint: 0,
            },
            status: isError ? 1 : 0,
            startFrame: 0,
            numberOfPackets: 0,
            errorCount: 0,
            actualLength: transferBuffer.length,
            transferBuffer,
            isoPacketDescriptor: EMPTY_BUFFER,
        });
    }

    /**
     * 
     * @param {SimulatedUsbDevice} targetDevice
     * @param {SubmitCommandBody} body
     */
    handleControlPacketBody(targetDevice, body) {
        let setup = this.readSetupBytes(body.setup);

        try {
            switch (setup.bmRequestType.rType) {
                case lib.bmRequestTypes.types.standard:
                    return this.handleStandardControlPacketBody(targetDevice, body, setup);

                case lib.bmRequestTypes.types.class:
                    return this.handleClassControlPacketBody(targetDevice, body, setup);

                case lib.bmRequestTypes.types.vendor:
                    return this.handleVendorControlPacketBody(targetDevice, body, setup);

                default:
                    throw new Error(`Unrecognized bmRequestType.rType '${setup.bmRequestType.rType}'; known types = ${util.inspect(lib.bmRequestTypes.types)}`);
            }
        } catch (err) {
            throw new Error(`Unable to handle setup packet '${util.inspect(setup)}'. Reason = ${util.inspect(err)}`);
        }
    }

    /**
     * 
     * @param {SimulatedUsbDevice} targetDevice
     * @param {SubmitCommandBody} body
     * @param {ParsedSetupBytes} setup
     */
    handleStandardControlPacketBody(targetDevice, body, setup) {
        switch (setup.bmRequestType.recipient) {
            case lib.bmRequestTypes.recipients.device:
                return this.handleStandardDeviceControlPacketBody(targetDevice, body, setup);

            case lib.bmRequestTypes.recipients.interface:
                return this.handleStandardInterfaceControlPacketBody(targetDevice, body, setup);

            case lib.bmRequestTypes.recipients.endpoint:
                return this.handleStandardEndpointControlPacketBody(targetDevice, body, setup);

            case lib.bmRequestTypes.recipients.other:
                return this.handleStandardOtherControlPacketBody(targetDevice, body, setup);

            default:
                throw new Error(`Unrecognized bmRequestType.recipient '${setup.bmRequestType.recipient}'; known types = ${util.inspect(lib.bmRequestTypes.recipients)}`);
        }
    }

    /**
     * 
     * @param {SimulatedUsbDevice} targetDevice
     * @param {SubmitCommandBody} body
     * @param {ParsedSetupBytes} setup
     */
    handleClassControlPacketBody(targetDevice, body, setup) {
        switch (setup.bmRequestType.recipient) {
            case lib.bmRequestTypes.recipients.device:
                return this.handleClassDeviceControlPacketBody(targetDevice, body, setup);

            case lib.bmRequestTypes.recipients.interface:
                return this.handleClassInterfaceControlPacketBody(targetDevice, body, setup);

            case lib.bmRequestTypes.recipients.endpoint:
                return this.handleClassEndpointControlPacketBody(targetDevice, body, setup);

            case lib.bmRequestTypes.recipients.other:
                return this.handleClassOtherControlPacketBody(targetDevice, body, setup);

            default:
                throw new Error(`Unrecognized bmRequestType.recipient '${setup.bmRequestType.recipient}'; known types = ${util.inspect(lib.bmRequestTypes.recipients)}`);
        }
    }

    /**
     * 
     * @param {SimulatedUsbDevice} targetDevice
     * @param {SubmitCommandBody} body
     * @param {ParsedSetupBytes} setup
     */
    handleClassDeviceControlPacketBody(targetDevice, body, setup) {
        throw new Error('Not Implemented');
    }
    
    /**
     * 
     * @param {SimulatedUsbDevice} targetDevice
     * @param {SubmitCommandBody} body
     * @param {ParsedSetupBytes} setup
     */
    handleClassInterfaceControlPacketBody(targetDevice, body, setup) {
        let iface = targetDevice._findIface();

        switch (iface.bInterfaceClass) {
            case lib.interfaceClasses.communicationsAndCdcControl:
                switch (setup.bRequest) {
                    case lib.bRequests.class.cdc.setLineCoding:
                        return this.handleCdcSetLineCodingPacket(targetDevice, iface, setup, body.transferBuffer);

                    case lib.bRequests.class.cdc.setControlLineState:
                        return this.handleCdcSetControlLineStatePacket(targetDevice, iface, setup, body.transferBuffer);

                    default:
                        throw new Error(`Unsupported CDC bRequest ${setup.bRequest}; supported bRequests = ${util.inspect(lib.bRequests.class.cdc)}`);
                }

            case lib.interfaceClasses.hid:
                switch (setup.bRequest) {
                    case lib.bRequests.class.hid.setIdle:
                        return this.handleHidSetIdlePacket(targetDevice, iface, setup);

                    default:
                        throw new Error(`Unsupported HID bRequest ${setup.bRequest}; supported bRequests = ${util.inspect(lib.bRequests.class.hid)}`);
                }

            default:
                throw new Error(`Unsupported bInterfaceClass '${iface.bInterfaceClass}'; supported bInterfaceClasses = ${util.inspect(lib.interfaceClasses)}`);
        }
    }
    
    /**
     * 
     * @param {SimulatedUsbDevice} targetDevice
     * @param {SubmitCommandBody} body
     * @param {ParsedSetupBytes} setup
     */
    handleClassEndpointControlPacketBody(targetDevice, body, setup) {
        throw new Error('Not Implemented');
    }
    
    /**
     * 
     * @param {SimulatedUsbDevice} targetDevice
     * @param {SubmitCommandBody} body
     * @param {ParsedSetupBytes} setup
     */
    handleClassOtherControlPacketBody(targetDevice, body, setup) {
        throw new Error('Not Implemented');
    }

    /**
     * 
     * @param {SimulatedUsbDevice} targetDevice
     * @param {SubmitCommandBody} body
     * @param {ParsedSetupBytes} setup
     */
    handleVendorControlPacketBody(targetDevice, body, setup) {
        throw new Error('Not Implemented');
    }

    /**
     * 
     * @param {SimulatedUsbDevice} targetDevice
     * @param {SubmitCommandBody} body
     * @param {ParsedSetupBytes} setup
     */
    handleStandardDeviceControlPacketBody(targetDevice, body, setup) {
        switch (setup.bRequest) {
            case lib.bRequests.standard.getStatus:
                return this.handleDeviceGetStatusPacket(targetDevice, setup);

            case lib.bRequests.standard.clearFeature:
                return this.handleDeviceClearFeaturePacket(targetDevice, setup);

            case lib.bRequests.standard.setFeature:
                return this.handleDeviceSetFeaturePacket(targetDevice, setup);

            case lib.bRequests.standard.setAddress:
                return this.handleSetAddressPacket(targetDevice, setup);

            case lib.bRequests.standard.getDescriptor:
                return this.handleGetDescriptorPacket(targetDevice, setup);

            case lib.bRequests.standard.setDescriptor:
                return this.handleSetDescriptorPacket(targetDevice, setup);

            case lib.bRequests.standard.getConfiguration:
                return this.handleGetConfigurationPacket(targetDevice, setup);

            case lib.bRequests.standard.setConfiguration:
                return this.handleSetConfigurationPacket(targetDevice, setup);

            case lib.bRequests.standard.getInterface:
                throw new Error('Unsupported Request: According to the spec, bRequest.GET_INTERFACE cannot be requested at the DEVICE level');

            case lib.bRequests.standard.setInterface:
                throw new Error('Unsupported Request: According to the spec, bRequest.SET_INTERFACE cannot be requested at the DEVICE level');

            case lib.bRequests.standard.synchFrame:
                throw new Error('Unsupported Request: According to the spec, bRequest.SYNCH_FRAME cannot be requested at the DEVICE level');

            default:
                throw new Error(`Unrecognized bRequest '${setup.bRequest}'; known bRequests = ${util.inspect(lib.bRequests)}`);
        }
    }
    
    /**
     * 
     * @param {SimulatedUsbDevice} targetDevice
     * @param {SubmitCommandBody} body
     * @param {ParsedSetupBytes} setup
     */
    handleStandardInterfaceControlPacketBody(targetDevice, body, setup) {
        let iface = targetDevice._findIface(null, setup.wIndex);

        switch (setup.bRequest) {
            case lib.bRequests.standard.getStatus:
                return this.handleInterfaceGetStatusPacket(targetDevice, setup);

            case lib.bRequests.standard.clearFeature:
                return this.handleInterfaceClearFeaturePacket(targetDevice, setup);

            case lib.bRequests.standard.setFeature:
                return this.handleInterfaceSetFeaturePacket(targetDevice, setup);

            case lib.bRequests.standard.setAddress:
                throw new Error('Unsupported Request: According to the spec, bRequest.SET_ADDRESS cannot be requested at the INTERFACE level');

            case lib.bRequests.standard.getDescriptor:
                if (iface && (iface.bInterfaceClass == lib.interfaceClasses.hid) && (setup.wValue >> 8 == 0x22) && ((setup.wValue & 0xff) == 0)) {
                    // unclear if this is actually how this should be handled, but im pretty sure this is the GET_HID_REPORT request
                    return this.handleGetHidReportDescriptorPacket(iface);
                } else {
                    throw new Error('Unsupported Request: According to the spec, bRequest.GET_DESCRIPTOR cannot be requested at the INTERFACE level');
                }

            case lib.bRequests.standard.setDescriptor:
                throw new Error('Unsupported Request: According to the spec, bRequest.SET_DESCRIPTOR cannot be requested at the INTERFACE level');

            case lib.bRequests.standard.getConfiguration:
                throw new Error('Unsupported Request: According to the spec, bRequest.GET_CONFIGURATION cannot be requested at the INTERFACE level');

            case lib.bRequests.standard.setConfiguration:
                throw new Error('Unsupported Request: According to the spec, bRequest.SET_CONFIGURATION cannot be requested at the INTERFACE level');

            case lib.bRequests.standard.getInterface:
                throw new Error('Unsupported Request: According to the usbipd source code, bRequest.GET_INTERFACE cannot be requested at the INTERFACE level');

            case lib.bRequests.standard.setInterface:
                return this.handleSetInterfacePacket(targetDevice, setup);

            case lib.bRequests.standard.synchFrame:
                throw new Error('Unsupported Request: According to the spec, bRequest.SYNCH_FRAME cannot be requested at the INTERFACE level');

            default:
                throw new Error(`Unrecognized bRequest '${setup.bRequest}'; known bRequests = ${util.inspect(lib.bRequests)}`);
        }
    }
    
    /**
     * 
     * @param {SimulatedUsbDevice} targetDevice
     * @param {SubmitCommandBody} body
     * @param {ParsedSetupBytes} setup
     */
    handleStandardEndpointControlPacketBody(targetDevice, body, setup){
        throw new Error('Not Implemented');
    }
    
    /**
     * 
     * @param {SimulatedUsbDevice} targetDevice
     * @param {SubmitCommandBody} body
     * @param {ParsedSetupBytes} setup
     */
    handleStandardOtherControlPacketBody(targetDevice, body, setup){
        throw new Error('Not Implemented');
    }

    /**
     * 
     * @param {SimulatedUsbDevice} targetDevice
     * @param {ParsedSetupBytes} setup
     */
    handleDeviceGetStatusPacket(targetDevice, setup) {
        throw new Error('Not Implemented');
    }

    /**
     * 
     * @param {SimulatedUsbDevice} targetDevice
     * @param {ParsedSetupBytes} setup
     */
    handleInterfaceGetStatusPacket(targetDevice, setup) {
        throw new Error('Not Implemented');
    }

    /**
     * 
     * @param {SimulatedUsbDevice} targetDevice
     * @param {ParsedSetupBytes} setup
     */
    handleDeviceClearFeaturePacket(targetDevice, setup) {
        throw new Error('Not Implemented');
    }

    /**
     * 
     * @param {SimulatedUsbDevice} targetDevice
     * @param {ParsedSetupBytes} setup
     */
    handleInterfaceClearFeaturePacket(targetDevice, setup) {
        throw new Error('Not Implemented');
    }

    /**
     * 
     * @param {SimulatedUsbDevice} targetDevice
     * @param {ParsedSetupBytes} setup
     */
    handleDeviceSetFeaturePacket(targetDevice, setup) {
        throw new Error('Not Implemented');
    }

    /**
     * 
     * @param {SimulatedUsbDevice} targetDevice
     * @param {ParsedSetupBytes} setup
     */
    handleInterfaceSetFeaturePacket(targetDevice, setup) {
        throw new Error('Not Implemented');
    }
    
    /**
     * 
     * @param {SimulatedUsbDevice} targetDevice
     * @param {ParsedSetupBytes} setup
     */
    handleSetAddressPacket(targetDevice, setup) {
        throw new Error('Not Implemented');
    }

    /**
     * Standard device request only (type = standard, recipient = device)
     * @param {SimulatedUsbDevice} targetDevice
     * @param {ParsedSetupBytes} setup
     */
    handleGetDescriptorPacket(targetDevice, setup) {
        let descriptorType = (setup.wValue & 0xff00) >> 8;
        let descriptorIndex = setup.wValue & 0x00ff;

        switch (descriptorType) {
            case lib.descriptorTypes.device:
                return this.handleGetDeviceDescriptorPacket(targetDevice, setup, descriptorIndex);

            case lib.descriptorTypes.config:
                return this.handleGetConfigDescriptorPacket(targetDevice, setup, descriptorIndex);

            case lib.descriptorTypes.string:
                return this.handleGetStringDescriptorPacket(targetDevice, setup, descriptorIndex);

            case lib.descriptorTypes.interface:
                return this.handleGetInterfaceDescriptorPacket(targetDevice, setup, descriptorIndex);

            case lib.descriptorTypes.endpoint:
                return this.handleGetEndpointDescriptorPacket(targetDevice, setup, descriptorIndex);

            default:
                throw new Error(`Unrecognized descriptorType '${descriptorType}'; known descriptorTypes = ${util.inspect(lib.descriptorTypes)}`)
        }
    }

    /**
     * 
     * @param {SimulatedUsbDevice} targetDevice
     * @param {ParsedSetupBytes} setup
     * @param {number} descriptorIndex
     */
    handleGetDeviceDescriptorPacket(targetDevice, setup, descriptorIndex) {
        return this.constructDeviceDescriptor(targetDevice, descriptorIndex, setup.wLength);
    }
    
    /**
     * 
     * @param {SimulatedUsbDevice} targetDevice
     * @param {ParsedSetupBytes} setup
     * @param {number} descriptorIndex
     */
    handleGetConfigDescriptorPacket(targetDevice, setup, descriptorIndex) {
        return this.constructConfigDescriptor(targetDevice, descriptorIndex, setup.wLength, true);
    }
    
    /**
     * 
     * @param {SimulatedUsbDevice} targetDevice
     * @param {ParsedSetupBytes} setup
     * @param {number} descriptorIndex
     */
    handleGetStringDescriptorPacket(targetDevice, setup, descriptorIndex) {
        if (!descriptorIndex) {
            return this.constructSupportedLangsDescriptor(targetDevice.spec.supportedLangs);
        } else {
            return this.constructStringDescriptorFromString(targetDevice.spec.stringDescriptors[descriptorIndex - 1]);
        }
    }

    /**
     * 
     * @param {number[]} supportedLangs
     */
    constructSupportedLangsDescriptor(supportedLangs) {
        return this.constructStringDescriptor(Buffer.concat(supportedLangs.map(langCode => {
            let langBuf = Buffer.allocUnsafe(2);
            langBuf.writeUInt16LE(langCode);
            return langBuf;
        })));
    }

    /**
     * 
     * @param {string} descriptor
     */
    constructStringDescriptorFromString(descriptor) {
        return this.constructStringDescriptor(Buffer.from(descriptor, UNICODE));
    }

    /**
     * 
     * @param {Buffer} descriptorBytes
     */
    constructStringDescriptor(descriptorBytes) {
        return Buffer.concat(
            [
                Buffer.from(
                    [
                        descriptorBytes.length + 2,
                        lib.descriptorTypes.string,
                    ]
                ),
                descriptorBytes,
            ]
        );
    }
    
    /**
     * 
     * @param {SimulatedUsbDevice} targetDevice
     * @param {ParsedSetupBytes} setup
     * @param {number} descriptorIndex
     */
    handleGetInterfaceDescriptorPacket(targetDevice, setup, descriptorIndex){
        throw new Error('Not Implemented');
    }
    
    /**
     * 
     * @param {SimulatedUsbDevice} targetDevice
     * @param {ParsedSetupBytes} setup
     * @param {number} descriptorIndex
     */
    handleGetEndpointDescriptorPacket(targetDevice, setup, descriptorIndex){
        throw new Error('Not Implemented');
    }

    
    /**
     * 
     * @param {SimulatedUsbDevice} targetDevice
     * @param {ParsedSetupBytes} setup
     */
    handleSetDescriptorPacket(targetDevice, setup) {
        throw new Error('Not Implemented');
    }
    
    /**
     * 
     * @param {SimulatedUsbDevice} targetDevice
     * @param {ParsedSetupBytes} setup
     */
    handleGetConfigurationPacket(targetDevice, setup) {
        throw new Error('Not Implemented');
    }
    
    /**
     * 
     * @param {SimulatedUsbDevice} targetDevice
     * @param {ParsedSetupBytes} setup
     */
    handleSetConfigurationPacket(targetDevice, setup) {
        targetDevice.spec.bConfigurationValue = setup.wValue;
        return EMPTY_BUFFER;
    }
    
    /**
     * 
     * @param {SimulatedUsbDevice} targetDevice
     * @param {ParsedSetupBytes} setup
     */
    handleGetInterfacePacket(targetDevice, setup) {
        throw new Error('Not Implemented');
    }

    /**
     * 
     * @param {SimulatedUsbDevice} targetDevice
     * @param {SimulatedUsbDeviceInterface} iface
     * @param {ParsedSetupBytes} setup
     * @param {Buffer} payload
     */
    handleCdcSetLineCodingPacket(targetDevice, iface, setup, payload) {
        iface._lineCoding = this.readCdcLineCoding(payload);
        return EMPTY_BUFFER;
    }

    /**
     * 
     * @param {Buffer} coding
     * @returns {CdcLineCoding}
     */
    readCdcLineCoding(coding) {
        return {
            dwDTERate: coding.readUInt32LE(),
            bCharFormat: coding[4],
            bParityType: coding[5],
            bDataBits: coding[6],
        };
    }

    /**
     * 
     * @param {SimulatedUsbDevice} targetDevice
     * @param {SimulatedUsbDeviceInterface} iface
     * @param {ParsedSetupBytes} setup
     * @param {Buffer} payload
     */
    handleCdcSetControlLineStatePacket(targetDevice, iface, setup, payload) {
        let oldLineState = iface._controlLineState;
        iface._controlLineState = payload;

        if (!payload.equals(oldLineState)) {
            targetDevice._notifyControlLineStateChanged(iface);
        }

        return EMPTY_BUFFER;
    }

    /**
     * 
     * @param {SimulatedUsbDevice} targetDevice
     * @param {SimulatedUsbDeviceInterface} iface
     * @param {ParsedSetupBytes} setup
     */
    handleHidSetIdlePacket(targetDevice, iface, setup) {
        iface._isIdle = true;
        return EMPTY_BUFFER;
    }
    
    /**
     * 
     * @param {SimulatedUsbDevice} targetDevice
     * @param {ParsedSetupBytes} setup
     */
    handleSetInterfacePacket(targetDevice, setup) {
        let iface = targetDevice._findIface(null, setup.wIndex & 0b0000_0000_1111_1111);

        if (!iface) {
            throw new Error(`No interface available for device with path "${targetDevice.spec.path}"`);
        } else {
            iface.bAlternateSetting = setup.wValue;
        }

        return EMPTY_BUFFER;
    }

    /**
     * 
     * @param {SimulatedUsbDeviceInterface} iface
     */
    handleGetHidReportDescriptorPacket(iface) {
        if (!iface.hidDescriptor || !iface.hidDescriptor.preCompiledReport) {
            this.emit('error', new Error('given interface has no hidDescriptor.preCompiledReport'));
            return EMPTY_BUFFER;
        } else {
            return iface.hidDescriptor.preCompiledReport;
        }
    }
    
    /**
     * 
     * @param {SimulatedUsbDevice} targetDevice
     * @param {ParsedSetupBytes} setup
     */
    handleSynchFramePacket(targetDevice, setup) {
        throw new Error('Not Implemented');
    }

    /**
     * 
     * @param {SimulatedUsbDevice} targetDevice
     * @param {SubmitCommandBody} bulk
     */
    handleBulkPacketBody(targetDevice, bulk) {
        switch (bulk.header.direction) {
            case lib.directions.in:
                if (targetDevice._pbops.count < 1) {
                    targetDevice._pbips.enqueue(bulk);
                } else {
                    let data = targetDevice._pbops.dequeue();

                    this.notifyAndWriteData(targetDevice._attachedSocket, this.constructBulkResponse(bulk, data));
                }
                break;

            case lib.directions.out:
                targetDevice.emit('bulkToDevice', bulk.transferBuffer);
                break;

            default:
                throw new Error(`Unrecognized direction '${setup}'; known directions = ${util.inspect(lib.directions)}`);
        }
    }

    /**
     * 
     * @param {SimulatedUsbDevice} targetDevice
     * @param {SubmitCommandBody} interrupt
     */
    handleInterruptPacketBody(targetDevice, interrupt) {
        if (interrupt.transferBuffer.length) {
            throw new Error(`I don't know what to do with an INTERRUPT packet when it has a transferBuffer.`);
        } else if (interrupt.isoPacketDescriptor.length) {
            throw new Error(`I don't know what to do with an INTERRUPT packet when it has an isoPacketDescriptor.`);
        } else {
            if (targetDevice._piops.count < 1) {
                targetDevice._piips.enqueue(interrupt);
            } else {
                let data = targetDevice._piops.dequeue();

                this.notifyAndWriteData(targetDevice._attachedSocket, this.constructInterruptResponse(interrupt, data));
            }
        }
    }

    /**
     * 
     * @param {SimulatedUsbDevice} sender
     * @param {SubmitCommandBody} bulkRequest
     * @param {Buffer} data
     */
    handleDeviceBulkData(sender, bulkRequest, data) {
        if (!bulkRequest) {
            sender._piops.enqueue(data);
        } else {
            this.notifyAndWriteData(sender._attachedSocket, this.constructBulkResponse(bulkRequest, data));
        }
    }

    /**
     * 
     * @param {SimulatedUsbDevice} sender
     * @param {SubmitCommandBody} interrupt
     * @param {Buffer} data
     */
    handleDeviceInterrupt(sender, interrupt, data) {
        if (!interrupt) {
            sender._piops.enqueue(data);
        } else {
            this.notifyAndWriteData(sender._attachedSocket, this.constructInterruptResponse(interrupt, data));
        }
    }

    /**
     * @typedef PacketParseOptions
     * @property {boolean} parseLeftoverData
     * @property {boolean} parseSetupPackets
     */

    /**
     * 
     * @param {Buffer} packet
     * @param {PacketParseOptions} [options]
     * @returns {UsbIpParsedPacket}
     */
    parsePacket(packet, options) {
        options = options || {};
        if (packet.length < 4) {
            throw new Error('Parse failure: length of packet must be at least 4');
        } else {
            let parsedObject = {};

            try {
                parsedObject.version = this.readVersion(packet.slice(0, 2));

                // version is only present in the 'operation' packets
                if (parsedObject.version == '0') {
                    delete parsedObject.version;
                    parsedObject.commandCode = this.readCommandCode(packet.slice(0, 4));
                    parsedObject.body = this.readCommandBody(parsedObject.commandCode, packet.slice(4), options);
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
     * @returns {SimulatedUsbDeviceSpec}
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
     * @param {number} version
     */
    decodeVersion(version) {
        let versionPieces = [];
        while (version) {
            versionPieces.push(version % 0x10);
            version >>= 4;
        }

        if (versionPieces.length == 0) {
            return '0';
        } else {
            return versionPieces.reverse().join('.');
        }
    }

    /**
     * 
     * @param {string} version
     */
    encodeVersion(version) {
        let encodedVersion = 0;
        let versionSplit = version.split('.');
        if (versionSplit.length > 4) {
            throw new Error(`'version' may have a maximum of 4 version numbers`);
        } else {
            for (let versionNibble of versionSplit.map(Number)) {
                if (isNaN(versionNibble)) {
                    throw new Error(`'version' is not formatted correctly (must be numbers seperated by '.' character)`);
                } else if (versionNibble < 0 || versionNibble > 0xf) {
                    throw new Error(`'version' numbers must each fit in a nibble; number '${versionNibble}' is too large/small`);
                } else {
                    encodedVersion <<= 4;
                    encodedVersion += versionNibble;
                }
            }

            return encodedVersion;
        }
    }

    /**
     * 
     * @param {Buffer} version
     */
    readVersion(version) {
        return this.decodeVersion(version.readUInt16BE());
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
     * @param {PacketParseOptions} [options]
     */
    readCommandBody(command, body, options) {
        try {
            let commandCode = lib.commands[command];
            switch (commandCode) {
                case lib.commands.USBIP_CMD_SUBMIT:
                    return this.readCmdSubmitBody(body, options);

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
     * @param {PacketParseOptions} [options]
     * @returns {SubmitCommandBody}
     */
    readCmdSubmitBody(body, options) {
        if (body.length < 44) {
            throw new Error('Submit command body must be at least 44 bytes long');
        } else {
            try {
                let header = this.readUsbipBasicHeader(body.slice(0, 16));
                let transferBufferLength = body.readUInt32BE(20);

                // if direction is not USBIP_DIR_OUT, we ignore the transferBufferLength
                let tBufferEndIndex = 44 + (header.direction == lib.directions.out ? transferBufferLength : 0);
                let startFrame = body.readUInt32BE(24);
                let isISO = startFrame != 0;
                let leftovers = body.slice(tBufferEndIndex);

                if (!isISO && leftovers.length > 0) {
                    var isoPacketDescriptor = EMPTY_BUFFER;
                    if (options.parseLeftoverData) {
                        var leftoverData = this.parsePacket(leftovers, options);
                    } else {
                        var leftoverData = leftovers;
                    }
                } else {
                    var leftoverData = null;
                    var isoPacketDescriptor = leftovers;
                }

                let setup = body.slice(36, 44);
                if (options.parseSetupPackets) {
                    if (setup.equals(EMPTY_SETUP_PACKET_BYTES)) {
                        setup = null; // contains no data
                    } else {
                        setup = this.readSetupBytes(setup);
                    }
                }

                return {
                    header,
                    transferFlags: body.readUInt32BE(16),
                    transferBufferLength,
                    startFrame,
                    numberOfPackets: body.readUInt32BE(28),
                    interval: body.readUInt32BE(32),
                    setup,
                    transferBuffer: body.slice(44, tBufferEndIndex),
                    isoPacketDescriptor,
                    leftoverData,
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
     * 
     * @param {number} seqnum
     * @param {number} devid
     * @param {number} direction
     * @param {number} endpoint
     */
    constructUsbipBasicHeader(seqnum, devid, direction, endpoint) {
        return Buffer.concat(
            [
                this.constructUInt32BE(seqnum),
                this.constructUInt32BE(devid),
                this.constructUInt32BE(direction),
                this.constructUInt32BE(endpoint),
            ]
        );
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
     * This format is defined by USB, _not_ usbip; meaning Little-Endian is used for multi-byte encoding
     * @param {Buffer} setup
     * @returns {ParsedSetupBytes}
     */
    readSetupBytes(setup) {
        return {
            bmRequestType: this.readBmRequestType(setup[0]),
            bRequest: setup[1],
            wValue: setup.readUInt16LE(2),
            wIndex: setup.readUInt16LE(4),
            wLength: setup.readUInt16LE(6),
        };
    }

    /**
     * 
     * @param {number} bmRequestType 8-bit mask
     * @returns {BmRequestType}
     */
    readBmRequestType(bmRequestType) {
        return {
            direction: bmRequestType & 0b1000_0000,
            rType: bmRequestType & 0b0110_0000,
            recipient: bmRequestType & 0b0001_1111,
        };
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
     * Protocol: USBIP
     * @param {SimulatedUsbDevice} device
     * @param {boolean} [includeInterfaceDescriptions] Default: false
     */
    constructDeviceDescription(device, includeInterfaceDescriptions) {
        let spec = device.spec;
        let defaultConfig = device._findConfig(spec.bConfigurationValue);
        let deviceDescriptionBytes = Buffer.concat(
            [
                this.constructPathBytes(spec.path),
                this.constructBusId(spec.busid),
                this.constructBusNum(spec.busnum),
                this.constructDevNum(spec.devnum),
                this.constructSpeed(spec.speed),
                this.constructVendorId(spec.idVendor),
                this.constructProductId(spec.idProduct),
                this.constructDeviceBcd(spec.bcdDevice),

                // single-byte entries (not really worth helper-methods)
                Buffer.from(
                    [
                        spec.bDeviceClass,
                        spec.bDeviceSubClass,
                        spec.bDeviceProtocol,
                        spec.bConfigurationValue,
                        spec.bNumConfigurations,
                        defaultConfig.bNumInterfaces,
                    ]
                ),
            ]
        );

        if (includeInterfaceDescriptions) {
            for (let deviceInterface of defaultConfig.interfaces) {
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
     * Protocol: USB
     * @param {SimulatedUsbDevice} device
     * @param {number} index
     * @param {number} [requestedLength]
     */
    constructDeviceDescriptor(device, index, requestedLength) {
        requestedLength = requestedLength || 0;
        let spec = device.spec;

        let deviceDescriptor = Buffer.from(
            [
                requestedLength,
                lib.descriptorTypes.device,
                0, 0, // bcdUsb (2-bytes, to be written later)
                spec.bDeviceClass,
                spec.bDeviceSubClass,
                spec.bDeviceProtocol,
                spec.bMaxPacketSize0,
                0, 0, // idVendor  (2-bytes, to be written later)
                0, 0, // idProduct (2-bytes, to be written later)
                0, 0, // bcdDevice (2-bytes, to be written later)
                spec.iManufacturer,
                spec.iProduct,
                spec.iSerialNumber,
                spec.bNumConfigurations,
            ]
        );

        if (!requestedLength) {
            deviceDescriptor.writeUInt8(deviceDescriptor.length);
        }

        // since this is USB protocol (not usbip), stuff is little-endian-encoded
        deviceDescriptor.writeUInt16LE(this.encodeVersion(spec.bcdUSB), 2);
        deviceDescriptor.writeUInt16LE(spec.idVendor, 8);
        deviceDescriptor.writeUInt16LE(spec.idProduct, 10);
        deviceDescriptor.writeUInt16LE(spec.bcdDevice, 12);

        if (requestedLength && requestedLength < deviceDescriptor.length) {
            return deviceDescriptor.slice(0, requestedLength)
        } else {
            return deviceDescriptor;
        }
    }

    /**
     * Protocol: USB
     * @param {SimulatedUsbDevice} device
     * @param {number} index
     * @param {number} [requestedLength]
     * @param {boolean} [includeInterfaceDescriptors]
     */
    constructConfigDescriptor(device, index, requestedLength, includeInterfaceDescriptors) {
        requestedLength = requestedLength || 0;
        let config = device._findConfig(index);

        let configDescriptor = Buffer.from(
            [
                0,    // bLength (to be written later)
                lib.descriptorTypes.config,
                0, 0, // wTotalLength (2-bytes, to be written later)
                config.bNumInterfaces,
                config.bConfigurationValue,
                config.iConfiguration,
                this.encodeConfigAttributes(config.bmAttributes),
                config.bMaxPower,
            ]
        );

        configDescriptor.writeUInt8(configDescriptor.length);

        if (includeInterfaceDescriptors) {
            for (let iface of config.interfaces) {
                configDescriptor = Buffer.concat(
                    [
                        configDescriptor,
                        this.constructInterfaceDescriptor(iface, null, true),
                    ]
                );
            }
        }

        // since this is USB protocol (not usbip), stuff is little-endian-encoded
        configDescriptor.writeUInt16LE(configDescriptor.length, 2);

        if (requestedLength && requestedLength < configDescriptor.length) {
            return configDescriptor.slice(0, requestedLength)
        } else {
            return configDescriptor;
        }
    }

    /**
     * 
     * @param {ConfigAttributes} attributes
     */
    encodeConfigAttributes(attributes) {
        return (attributes.selfPowered ? 0b0100_0000 : 0)
            | (attributes.remoteWakeup ? 0b0010_0000 : 0);
    }

    /**
     * 
     * @param {SimulatedUsbDeviceInterface} iface
     */
    constructDeviceInterfaceDescription(iface) {
        return Buffer.from(
            [
                iface.bInterfaceClass,
                iface.bInterfaceSubClass,
                iface.bInterfaceProtocol,
                0,  // padding byte for alignment
            ]
        );
    }

    /**
     * 
     * @param {Buffer} interfaceList
     * @returns {Generator<SimulatedUsbDeviceInterfaceSpec, void, unknown>}
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
     * @param {SimulatedUsbDeviceInterface} iface
     * @param {number} requestedLength
     * @param {boolean} includeEndpointDescriptors
     */
    constructInterfaceDescriptor(iface, requestedLength, includeEndpointDescriptors) {
        requestedLength = requestedLength || 0;
        let ifaceDescriptor = Buffer.from(
            [
                requestedLength,
                lib.descriptorTypes.interface,
                iface.bInterfaceNumber,
                iface.bAlternateSetting,
                iface.bNumEndpoints,
                iface.bInterfaceClass,
                iface.bInterfaceSubClass,
                iface.bInterfaceProtocol,
                iface.iInterface,
            ]
        );

        if (!requestedLength) {
            ifaceDescriptor.writeUInt8(ifaceDescriptor.length);
        }

        if (iface.hidDescriptor) {
            ifaceDescriptor = Buffer.concat(
                [
                    ifaceDescriptor,
                    this.constructHidDescriptor(iface.hidDescriptor),
                ]
            );
        }

        if (iface.communicationsDescriptors.length > 0) {
            ifaceDescriptor = Buffer.concat(
                [
                    ifaceDescriptor,
                    ...iface.communicationsDescriptors,
                ]
            );
        }

        if (includeEndpointDescriptors) {
            for (let endpoint of iface.endpoints) {
                ifaceDescriptor = Buffer.concat(
                    [
                        ifaceDescriptor,
                        this.constructEndpointDescriptor(endpoint),
                    ]
                );
            }
        }

        if (requestedLength && requestedLength < ifaceDescriptor.length) {
            return ifaceDescriptor.slice(0, requestedLength)
        } else {
            return ifaceDescriptor;
        }
    }

    /**
     * 
     * @param {SimulatedUsbDeviceHidDescriptor} hidDescriptor
     */
    constructHidDescriptor(hidDescriptor) {
        let descriptor = Buffer.from(
            [
                0,    // bLength (to be written later)
                0x21,
                0, 0, // bcdHID (2-bytes; to be written later)
                hidDescriptor.bCountryCode,
                1,    // bNumDescriptors (should be one: the HID report)
                0x22,
                0, 0, // wDescriptorLength (2-bytes; to be written later)
            ]
        );

        descriptor.writeUInt8(descriptor.length);

        // since this is USB protocol (not usbip), stuff is little-endian-encoded
        descriptor.writeUInt16LE(hidDescriptor.bcdHID, 2);
        descriptor.writeUInt16LE(hidDescriptor.wDescriptorLength, 7);

        return descriptor;
    }

    /**
     * 
     * @param {SimulatedUsbDeviceEndpoint} endpoint
     */
    constructEndpointDescriptor(endpoint) {
        let endpointDescriptor = Buffer.from(
            [
                0, // bLength (to be written later)
                lib.descriptorTypes.endpoint,
                this.encodeEndpointAddress(endpoint.bEndpointAddress),
                this.encodeEndpointAttributes(endpoint.bmAttributes),
                0, 0, // wMaxPacketSize (2-bytes, to be written later)
                endpoint.bInterval,
            ]
        );

        endpointDescriptor.writeUInt8(endpointDescriptor.length);

        // since this is USB protocol (not usbip), stuff is little-endian-encoded
        endpointDescriptor.writeUInt16LE(endpoint.wMaxPacketSize, 4);

        return endpointDescriptor;
    }

    /**
     * 
     * @param {EndpointAddress} address
     */
    encodeEndpointAddress(address) {
        return (address.direction << 7)
            | (address.endpointNumber & 0b0000_1111);
    }

    /**
     * 
     * @param {EndpointAttributes} attributes
     */
    encodeEndpointAttributes(attributes) {
        return (attributes.usageType & 0b0011_0000)
            | (attributes.synchronisationType & 0b0000_1100)
            | (attributes.transferType & 0b0000_0011);
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

    /**
     * 
     * @param {SubmitCommandBody} reqBody
     * @param {Buffer} transferBuffer
     */
    constructRetSubmitPacket(reqBody, transferBuffer) {
        let reqHeader = reqBody.header;
        return Buffer.concat(
            [
                lib.commands.USBIP_RET_SUBMIT,
                this.constructUsbipBasicHeader(reqHeader.seqnum, 0, reqHeader.direction, 0),
                this.constructStatusBytes(0),
                this.constructUInt32BE(transferBuffer.length),
                Buffer.alloc(8), // start_frame and number_of_packets will both be zero because this is not an ISO transfer
                Buffer.alloc(4), // TODO: error_count; not sure how to handle this yet
                Buffer.alloc(8), // padding
                transferBuffer,
            ]
        );
    }

    /**
     * 
     * @param {SubmitCommandBody} bulkRequest
     * @param {Buffer} bData
     */
    constructBulkResponse(bulkRequest, bData) {
        return this.constructRetSubmitPacket(bulkRequest, bData);
    }
    
    /**
     * 
     * @param {SubmitCommandBody} interruptRequest
     * @param {Buffer} iData
     */
    constructInterruptResponse(interruptRequest, iData) {
        return this.constructRetSubmitPacket(interruptRequest, iData);
    }
}

/** */
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

        /** @type {Map<SimulatedUsbDevice, Queue<SubmitCommandBody>>} */
        this._interruptQMap = new Map();
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
        return this.getDeviceWith(device => device.spec.path == pathQuery);
    }

    /**
     * 
     * @param {string} busIdQuery
     */
    getDeviceByBusId(busIdQuery) {
        return this.getDeviceWith(device => device.spec.busid == busIdQuery);
    }

    /**
     * 
     * @param {number} devIdQuery
     */
    getDeviceByDevId(devIdQuery) {
        let busNum = devIdQuery >> 16;
        let devNum = devIdQuery % 0x10000;

        return this.getDeviceWith(device => device.spec.busnum == busNum && device.spec.devnum == devNum);
    }
}

/**
 * @typedef SimulatedUsbDeviceSpec
 * @property {string} [path]   Will be automatically set by server simulator when exported (if not present)
 * @property {string} [busid]  Will be automatically set by server simulator when exported (if not present)
 * @property {number} [busnum] Will be automatically set by server simulator when exported (if not present)
 * @property {number} [devnum] Will be automatically set by server simulator when exported (if not present)
 * @property {number} speed
 * @property {number} idVendor
 * @property {number} idProduct
 * @property {number} bcdDevice device revision number
 * @property {string} bcdUSB USB specification version (Formatted such that version 2.1 is represented as '0.2.1.0')
 * @property {number} bDeviceClass
 * @property {number} bDeviceSubClass
 * @property {number} bDeviceProtocol
 * @property {8 | 16 | 32 | 64} bMaxPacketSize0 Maximum packet size for Endpoint zero
 * @property {number} [bConfigurationValue]
 * @property {number} [iManufacturer]
 * @property {number} [iProduct]
 * @property {number} [iSerialNumber]
 * @property {number} [bNumConfigurations]
 * @property {SimulatedUsbDeviceConfiguration[]} configurations
 * @property {number[]} [supportedLangs]
 * @property {string[]} [stringDescriptors]
 * @property {SimulatedUsbDeviceEndpoint[]} [endpointShortcutMap]
 */

/**
 * @typedef SimulatedUsbDeviceConfiguration
 * @property {number} [bConfigurationValue]
 * @property {number | ConfigAttributes} bmAttributes
 * @property {number} bMaxPower in increments of 2mA (for example, if max power is 100mA, bMaxPower should be 50)
 * @property {number} [bNumInterfaces]
 * @property {SimulatedUsbDeviceInterface[]} [interfaces]
 * @property {number} iConfiguration
 * @property {number} [_bInterfaceNumber] Represents the "currently selected" interface (not part of spec apparently)
 */

/**
 * @typedef ConfigAttributes
 * @property {boolean} selfPowered
 * @property {boolean} remoteWakeup
 */

/**
 * @typedef SimulatedUsbDeviceInterface
 * @property {number} [bInterfaceNumber]
 * @property {number} [bAlternateSetting]
 * @property {number} bInterfaceClass
 * @property {number} bInterfaceSubClass
 * @property {number} bInterfaceProtocol
 * @property {Buffer[]} [communicationsDescriptors]
 * @property {SimulatedUsbDeviceHidDescriptor} [hidDescriptor] Only necessary if device is class HID
 * @property {number} [bNumEndpoints]
 * @property {SimulatedUsbDeviceEndpoint[]} [endpoints]
 * @property {number} [iInterface]
 * @property {CdcLineCoding} [_lineCoding]
 * @property {Buffer} [_controlLineState]
 * @property {boolean} [_isIdle]
 */

/**
 * @typedef CdcLineCoding
 * @property {number} dwDTERate
 * @property {number} bCharFormat
 * @property {number} bParityType
 * @property {number} bDataBits
 */

/**
 * @typedef SimulatedUsbDeviceHidDescriptor
 * @property {number} bcdHID
 * @property {number} [bCountryCode]
 * @property {number} [wDescriptorLength]
 * @property {HidReportDescriptorReport} [report]
 * @property {Buffer} [preCompiledReport]
 */

/**
 * Not supported yet (why would we ever?)
 * @typedef HidReportDescriptorReport
 */

/**
 * @typedef SimulatedUsbDeviceEndpoint
 * @property {EndpointAddress} bEndpointAddress
 * @property {EndpointAttributes} bmAttributes
 * @property {number} wMaxPacketSize
 * @property {number} bInterval
 */

/**
 * @typedef EndpointAddress
 * @property {number} [endpointNumber]
 * @property {0 | 1} direction
 */

/**
 * @typedef EndpointAttributes
 * @property {number} transferType
 * @property {number} [synchronisationType] required only for isochronous transferType
 * @property {number} [usageType] required only for isochronous transferType
 */

/** */
class SimulatedUsbDevice extends EventEmitter {
    /**
     * Event fired when the device is attached by a usbip client
     * 
     * @event SimulatedUsbDevice#attached
     * @type {object}
     * 
     */

    /**
     * Event fired when the device is detached by a usbip client
     * 
     * @event SimulatedUsbDevice#detached
     * @type {object}
     */

    /**
     * Event fired when the device has its control line state changed by the host driver
     *
     * @event SimulatedUsbDevice#controlLineStateChanged
     * @type {object}
     * @property {SimulatedUsbDeviceInterface} iface
     */

    /**
     * Event fired when the device receives bulk data
     * 
     * @event SimulatedUsbDevice#bulkToDevice
     * @type {object}
     * @property {Buffer} data
     */

    /**
     * Event fired when the device sends bulk data
     * 
     * @event SimulatedUsbDevice#bulkToHost
     * @type {object}
     * @property {Buffer} data
     */

    /**
     * Event fired when the device writes an interrupt packet
     * 
     * @event SimulatedUsbDevice#interrupt
     * @type {object}
     * @property {Buffer} data
     */
        
    /**
     * 
     * @param {SimulatedUsbDeviceSpec} spec
     */
    constructor(spec) {
        super();
        this.spec = spec;

        /** @type {net.Socket} */
        this._attachedSocket = null;

        /**
         * Pending-Bulk-In-Packets
         * @type {Queue<SubmitCommandBody>}
         */
        this._pbips = new Queue();

        /**
         * Pending-Bulk-Out-Packets
         * @type {Queue<Buffer>}
         */
        this._pbops = new Queue();

        /**
         * Pending-Interrupt-In-Packets
         * @type {Queue<SubmitCommandBody>}
         */
        this._piips = new Queue();

        /**
         * Pending-Interrupt-Out-Packets
         * @type {Queue<Buffer>}
         */
        this._piops = new Queue();
    }

    [util.inspect.custom](depth, opts) {
        return 'SimulatedUsbDevice ' + util.inspect({
            spec: this.spec,
            _pbips: this._pbips,
            _pbops: this._pbops,
            _piips: this._piips,
            _piops: this._piops,
        }, null, depth - 1);
    }

    /**
     * 
     * @param {number} [configQuery]
     * @returns {SimulatedUsbDeviceConfiguration}
     */
    _findConfig(configQuery) {
        if (!configQuery) {
            if (!this.spec.bConfigurationValue) {
                return this.spec.configurations.find(conf => !!conf);
            } else {
                return this._findConfig(this.spec.bConfigurationValue);
            }
        } else {
            return this.spec.configurations.find(conf => conf.bConfigurationValue == configQuery);
        }
    }

    /**
     * 
     * @param {SimulatedUsbDeviceConfiguration} [config]
     * @param {number} [ifaceQuery]
     * @returns {SimulatedUsbDeviceInterface}
     */
    _findIface(config, ifaceQuery) {
        if (!config) {
            return this._findIface(this._findConfig() || {}, ifaceQuery);
        } else if (!ifaceQuery) {
            if (!config._bInterfaceNumber) {
                return config.interfaces.find(iface => !!iface);
            } else {
                return this._findIface(config, config._bInterfaceNumber);
            }
        } else {
            return config.interfaces.find(iface => iface.bInterfaceNumber == ifaceQuery);
        }
    }

    /**
     * 
     * @param {SimulatedUsbDeviceInterface} iface
     * @param {number} endpointNumberQuery
     * @returns {SimulatedUsbDeviceEndpoint}
     */
    _findEndpoint(iface, endpointNumberQuery) {
        if (!iface) {
            let ep = this._findEndpoint(this._findIface() || {}, endpointNumberQuery);
            if (ep && endpointNumberQuery != null) {
                return ep;
            } else if (endpointNumberQuery != null) {
                return this.spec.endpointShortcutMap[endpointNumberQuery];
            } else {
                return null;
            }
        } else if (!endpointNumberQuery) {
            return iface.endpoints.find(ep => !!ep);
        } else {
            return iface.endpoints.find(ep => ep.bEndpointAddress.endpointNumber == endpointNumberQuery);
        }
    }

    /**
     * 
     * @param {SimulatedUsbDeviceInterface} iface
     */
    _notifyControlLineStateChanged(iface) {
        this.emit('controlLineStateChanged', iface);
    }

    /**
     * 
     * @param {Buffer} data
     * @fires SimulatedUsbDevice#bulkToHost
     */
    bulk(data) {
        if (this._pbips.count < 1) {
            this._pbops.enqueue(data);
        } else {
            this.emit('bulkToHost', this._pbips.dequeue(), data);
        }
    }

    /**
     * 
     * @param {Buffer} data
     * @fires SimulatedUsbDevice#interrupt
     */
    interrupt(data) {
        if (this._piips.count < 1) {
            this._piops.enqueue(data);
        } else {
            this.emit('interrupt', this._piips.dequeue(), data);
        }
    }
}

module.exports = {
    UsbIpServerSim,
    SimulatedUsbDevice,

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
            console.log(`Wrote ${util.inspect(data)} ${util.inspect(server._protocolLayer.parsePacket(data, { parseLeftoverData: true, parseSetupPackets: true }), false, Infinity)}`);
        }
    });

    server.on('protocolError', console.error);

    let scannerDevice = new SimulatedUsbDevice({
        //busnum: 3,
        //devnum: 1,
        //path: '/sys/devices/simulation/usb3/3-1',
        //busid: '3-1',
        speed: 3,
        idVendor: 1008,
        idProduct: 825,
        bcdDevice: 0x0105,
        bDeviceClass: 2,
        bDeviceSubClass: 0,
        bDeviceProtocol: 0,
        bConfigurationValue: 0, // dont have example of this
        bcdUSB: '2.0.0',
        bMaxPacketSize0: 64,
        iManufacturer: 1,
        iProduct: 2,
        iSerialNumber: 3,
        configurations: [
            {
                bConfigurationValue: 1,
                iConfiguration: 4,
                bmAttributes: {
                    selfPowered: false,
                    remoteWakeup: false,
                },
                bMaxPower: 200, // 400mA
                interfaces: [
                    {
                        bInterfaceNumber: 0,
                        bAlternateSetting: 0,
                        bInterfaceClass: 0x02,
                        bInterfaceSubClass: 0x02,
                        bInterfaceProtocol: 0x01,
                        iInterface: 5,
                        communicationsDescriptors: [
                            Buffer.from([0x05, 0x24, 0x00, 0x10, 0x01,]),
                            Buffer.from([0x04, 0x24, 0x02, 0x02,]),
                            Buffer.from([0x05, 0x24, 0x06, 0x00, 0x01,]),
                            Buffer.from([0x05, 0x24, 0x01, 0x03, 0x01,]),
                        ],
                        endpoints: [
                            {
                                bEndpointAddress: {
                                    direction: lib.directions.in,
                                    endpointNumber: 1,
                                },
                                bmAttributes: {
                                    transferType: lib.transferTypes.interrupt,
                                },
                                wMaxPacketSize: 16,
                                bInterval: 1,
                            },
                        ],
                    },
                    {
                        bInterfaceNumber: 1,
                        bAlternateSetting: 0,
                        bNumEndpoints: 2,
                        bInterfaceClass: 0x0a,
                        bInterfaceSubClass: 0x00,
                        bInterfaceProtocol: 0x00,
                        iInterface: 7,
                        endpoints: [
                            {
                                bEndpointAddress: {
                                    direction: lib.directions.in,
                                    endpointNumber: 2,
                                },
                                bmAttributes: {
                                    transferType: lib.transferTypes.bulk,
                                },
                                wMaxPacketSize: 64,
                                bInterval: 255,
                            },
                            {
                                bEndpointAddress: {
                                    direction: lib.directions.out,
                                    endpointNumber: 3,
                                },
                                bmAttributes: {
                                    transferType: lib.transferTypes.bulk,
                                },
                                wMaxPacketSize: 64,
                                bInterval: 255,
                            }
                        ],
                    },
                ],
            },
        ],
        stringDescriptors: [
            'HP',                    // descriptor 1 (iManufacturer)
            'HP Imager Scanner',     // descriptor 2 (iProduct)
            'S/N VNC8030217',        // descriptor 3 (iSerialNumber)
            'Default Configuration', // descriptor 4 (iConfiguration)
            'Interrupt Interface',   // descriptor 5 (iInterface)
            '',                      // descriptor 6 (not used?)
            'Bulk Interface',        // descriptor 7 (iInterface)
        ],
    });

    let mouseDevice = new SimulatedUsbDevice({
        bcdDevice: 17153,
        bcdUSB: '2.0.0',
        speed: 3,
        idVendor: 16700,
        idProduct: 12306,
        bDeviceClass: 0,
        bDeviceSubClass: 0,
        bDeviceProtocol: 0,
        bMaxPacketSize0: 8,
        iManufacturer: 1,
        iProduct: 2,
        iSerialNumber: 0,
        bConfigurationValue: 0,
        configurations: [
            {
                iConfiguration: 3,
                bMaxPower: 50, // 100mA
                bmAttributes: {
                    selfPowered: false,
                    remoteWakeup: true,
                },
                interfaces: [
                    {
                        iInterface: 4,
                        bInterfaceClass: 0x03, // HID
                        bInterfaceSubClass: 0x01,
                        bInterfaceProtocol: 0x02, // Mouse
                        bAlternateSetting: 0,
                        hidDescriptor: {
                            bcdHID: 0x0111,
                            bCountryCode: 0, // 0 means not supported
                            preCompiledReport: Buffer.from(
                                [
                                                                                                            0x05, 0x01, 0x09, 0x02, // pulled from wireshark
                                    0xa1, 0x01, 0x09, 0x01, 0xa1, 0x00, 0x05, 0x09, 0x19, 0x01, 0x29, 0x03, 0x15, 0x00, 0x25, 0x01, // pulled from wireshark
                                    0x75, 0x01, 0x95, 0x03, 0x81, 0x02, 0x75, 0x05, 0x95, 0x01, 0x81, 0x01, 0x05, 0x01, 0x09, 0x30, // pulled from wireshark
                                    0x09, 0x31, 0x09, 0x38, 0x15, 0x81, 0x25, 0x7f, 0x75, 0x08, 0x95, 0x03, 0x81, 0x06, 0xc0, 0xc0, // pulled from wireshark
                                ]
                            ),
                        },
                        endpoints: [
                            {
                                bEndpointAddress: {
                                    direction: lib.directions.in,
                                },
                                bmAttributes: {
                                    transferType: lib.transferTypes.interrupt,
                                },
                                wMaxPacketSize: 5,
                                bInterval: 0x0a,
                            },
                        ],
                    },
                ],
            },
        ],
        supportedLangs: [0x0409], // english only
        stringDescriptors: [
            'Dell',                   // descriptor 1 (iManufacturer)
            'Dell USB Optical Mouse', // descriptor 2 (iProduct)
            'Default Configuration',  // descriptor 3 (iConfiguration)
            'Default Interface',      // descriptor 4 (iInterface)
        ],
    });

    setInterval(() => {
        return scannerDevice && mouseDevice; // for debugging
    }, 10000);

    let smartWaterUpc = Buffer.from('786162338006\r');
    scannerDevice.on('attached', () => {
        console.log(`scanner attached, will begin sending data in 5 seconds`);
        setTimeout(() => {
            setInterval(() => {
                // WAIT until the controller is ready for us to receive data
                if (scannerDevice._piips.count > 0) {
                    // SERIAL STATE (means data incoming?) --------------------------------------------- vvvv -----
                    scannerDevice.interrupt(Buffer.from([0xa1, 0x20, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x80, 0x00]));

                    // UPC
                    scannerDevice.bulk(smartWaterUpc);

                    // SERIAL STATE (means data no longer incoming?) ----------------------------------- vvvv -----
                    scannerDevice.interrupt(Buffer.from([0xa1, 0x20, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00]));
                }
            }, 10000);
        }, 5000);
    });

    // "mouse context"
    let mcx = { x: 10, y: -5, xDirection: 1, yDirection: -2, buf: Buffer.alloc(4) };

    const LIMIT = 20;
    mouseDevice.on('attached', () => {
        console.log(`mouse attached, will begin sending interrupts in 5 seconds`);
        setTimeout(() => {
            setInterval(() => {
                mcx.x += mcx.xDirection;
                mcx.y += mcx.yDirection;

                if (Math.abs(mcx.x) >= LIMIT) {
                    mcx.xDirection *= -1;
                }

                if (Math.abs(mcx.y) >= LIMIT) {
                    mcx.yDirection *= -1;
                }

                mcx.buf.writeInt8(mcx.x, 1);
                mcx.buf.writeInt8(mcx.y, 2);

                mouseDevice.interrupt(mcx.buf);
            }, 40);
        }, 5000);
    });

    server.exportDevice(scannerDevice);
    server.exportDevice(mouseDevice);

    server.listen('0.0.0.0');

    //collectTestData();
}

function collectTestData() {
    let fs = require('fs');
    let proto = new UsbIpProtocolLayer();
    let data = require('./test_data.js').data;

    fs.writeFileSync('test.txt', '');
    for (let key in data) {
        fs.appendFileSync('test.txt', `${key} ${util.inspect(proto.parsePacket(Buffer.from(data[key]), { parseSetupPackets: true, parseLeftoverData: true }), false, Infinity)}`);
        fs.appendFileSync('test.txt', '-----------------------------------------------------------------------------------------------------------------------------------------------------------\r\n');
    }
}
