
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
     * Assign values which were left out by the user.
     * @param {SimulatedUsbDeviceSpec} spec
     * @param {number} defaultDeviceNumber
     */
    _normalizeDeviceSpec(spec, defaultDeviceNumber) {
        if (!spec.bcdUSB) {
            spec.bcdUSB = '0';
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
            let usbSpecMajorVersion = spec.bcdUSB.split('.').slice(-3, -2)[0] || '0';
            spec.path = posix.join(this._server.devicesDirectory, `usb${usbSpecMajorVersion}`, spec.busid);
        }

        if (spec.iManufacturer == null) spec.iManufacturer = 0;
        if (spec.iProduct == null) spec.iProduct = 0;
        if (spec.iSerialNumber == null) spec.iSerialNumber = 0;

        if (!spec.configurations) {
            spec.configurations = [];
        }

        if (!spec.bNumConfigurations) {
            spec.bNumConfigurations = spec.configurations.length;
        }

        if (spec.configurations.length < 1) {
            throw new Error('Specification must contain at least one configuration object');
        }

        if (!spec.stringDescriptors) {
            spec.stringDescriptors = [];
        }

        if (spec.stringDescriptors.length < 1) {
            spec.stringDescriptors.push('English');
        }

        for (let configKey in spec.configurations) {
            this._normalizeDeviceConfig(spec.configurations[configKey], configKey + 1);
        }
    }

    /**
     * 
     * @param {SimulatedUsbDeviceConfiguration} config
     * @param {number} defaultConfigNumber
     */
    _normalizeDeviceConfig(config, defaultConfigNumber) {
        if (config.bConfigurationValue == null) {
            config.bConfigurationValue = defaultConfigNumber
        }

        if (!config.interfaces) {
            config.interfaces = [];
        }

        if (!config.bNumInterfaces) {
            config.bNumInterfaces = config.interfaces.length;
        }

        if (config.iConfiguration == null) config.iConfiguration = 0;

        for (let interfaceKey in config.interfaces) {
            this._normalizeDeviceInterface(config.interfaces[interfaceKey], interfaceKey + 1);
        }
    }

    /**
     * 
     * @param {SimulatedUsbDeviceInterface} iface
     * @param {number} defaultIfaceNumber
     */
    _normalizeDeviceConfig(iface, defaultIfaceNumber) {
        if (iface.bInterfaceNumber == null) {
            iface.bInterfaceProtocol = defaultIfaceNumber
        }

        if (!iface.endpoints) {
            iface.endpoints = [];
        }

        if (!iface.bNumEndpoints) {
            iface.bNumEndpoints = iface.endpoints.length;
        }

        if (iface.iInterface == null) iface.iInterface = 0;

        for (let endpointKey in iface.endpoints) {
            this._normalizeDeviceEndpoint(iface.endpoints[endpointKey], endpointKey + 1);
        }
    }

    /**
     * 
     * @param {SimulatedUsbDeviceEndpoint} endpoint
     * @param {number} defaultEndpointNumber
     */
    _normalizeDeviceEndpoint(endpoint, defaultEndpointNumber) {
        if (!endpoint.bEndpointAddress) endpoint.bEndpointAddress = {};
        if (!endpoint.bmAttributes) endpoint.bmAttributes = {};

        if (!endpoint.bEndpointAddress.endpointNumber) {
            endpoint.bEndpointAddress.endpointNumber = defaultEndpointNumber;
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
     * @param {Error} err
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
                matchingDevice.on('interrupt', data => this.handleDeviceInterrupt(matchingDevice, data));
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
                        let endpoint = this.server.getEndpoint(targetDevice, body.header.endpoint);
                        transferType = endpoint.bmAttributes.transferType;
                    }

                    switch (transferType) {
                        case lib.transferTypes.control:
                            this.handleControlPacketBody(targetDevice, body);
                            break;

                        case lib.transferTypes.isochronous:
                            throw new Error('Not Implemented');
                            break;

                        case lib.transferTypes.bulk:
                            throw new Error('Not Implemented');
                            break;

                        case lib.transferTypes.interrupt:
                            this.handleInterruptPacketBody(targetDevice, body);
                            break;

                        default:
                            throw new Error(`Unrecognized endpoint; known endpoints = ${util.inspect(lib.transferTypes)}`);
                    }
                } catch (err) {
                    this.error(new Error(`Unable to handle submit command to endpoint '${body.header.endpoint}'. Reason = ${err}`));
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
     * @param {SimulatedUsbDevice} targetDevice
     * @param {SubmitCommandBody} body
     */
    handleControlPacketBody(targetDevice, body) {
        let setup = this.readSetupBytes(body.setup);

        try {
            switch (setup.bmRequestType.rType) {
                case lib.bmRequestTypes.types.standard:
                    this.handleStandardControlPacketBody(targetDevice, body, setup);
                    break;

                case lib.bmRequestTypes.types.class:
                    this.handleClassControlPacketBody(targetDevice, body, setup);
                    break;

                case lib.bmRequestTypes.types.vendor:
                    this.handleVendorControlPacketBody(targetDevice, body, setup);
                    break;

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
                this.handleStandardDeviceControlPacketBody(targetDevice, body, setup);
                break;

            case lib.bmRequestTypes.recipients.interface:
                this.handleStandardInterfaceControlPacketBody(targetDevice, body, setup);
                break;

            case lib.bmRequestTypes.recipients.endpoint:
                this.handleStandardEndpointControlPacketBody(targetDevice, body, setup);
                break;

            case lib.bmRequestTypes.recipients.other:
                this.handleStandardOtherControlPacketBody(targetDevice, body, setup);
                break;

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
            case lib.bRequests.getStatus:
                this.handleGetStatusPacket(targetDevice, setup);
                break;

            case lib.bRequests.clearFeature:
                this.handleClearFeaturePacket(targetDevice, setup);
                break;

            case lib.bRequests.setFeature:
                this.handleSetFeaturePacket(targetDevice, setup);
                break;

            case lib.bRequests.setAddress:
                this.handleSetAddressPacket(targetDevice, setup);
                break;

            case lib.bRequests.getDescriptor:
                this.handleGetDescriptorPacket(targetDevice, setup);
                break;

            case lib.bRequests.setDescriptor:
                this.handleSetDescriptorPacket(targetDevice, setup);
                break;

            case lib.bRequests.getConfiguration:
                this.handleGetConfigurationPacket(targetDevice, setup);
                break;

            case lib.bRequests.setConfiguration:
                this.handleSetConfigurationPacket(targetDevice, setup);
                break;

            case lib.bRequests.getInterface:
                this.handleGetInterfacePacket(targetDevice, setup);
                break;

            case lib.bRequests.setInterface:
                this.handleSetInterfacePacket(targetDevice, setup);
                break;

            case lib.bRequests.synchFrame:
                this.handleSynchFramePacket(targetDevice, setup);
                break;

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
        throw new Error('Not Implemented');
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
    handleGetStatusPacket(targetDevice, setup) {
        throw new Error('Not Implemented');
    }
    
    /**
     * 
     * @param {SimulatedUsbDevice} targetDevice
     * @param {ParsedSetupBytes} setup
     */
    handleClearFeaturePacket(targetDevice, setup) {
        throw new Error('Not Implemented');
    }
    
    /**
     * 
     * @param {SimulatedUsbDevice} targetDevice
     * @param {ParsedSetupBytes} setup
     */
    handleSetFeaturePacket(targetDevice, setup) {
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
        let descriptorType = setup.wValue & 0xff00;
        let descriptorIndex = setup.wValue & 0x00ff;

        switch (descriptorType) {
            case lib.descriptorTypes.device:
                this.handleGetDeviceDescriptorPacket(targetDevice, setup, descriptorIndex);
                break;

            case lib.descriptorTypes.config:
                this.handleGetConfigDescriptorPacket(targetDevice, setup, descriptorIndex);
                break;

            case lib.descriptorTypes.string:
                this.handleGetStringDescriptorPacket(targetDevice, setup, descriptorIndex);
                break;

            case lib.descriptorTypes.interface:
                this.handleGetInterfaceDescriptorPacket(targetDevice, setup, descriptorIndex);
                break;

            case lib.descriptorTypes.endpoint:
                this.handleGetEndpointDescriptorPacket(targetDevice, setup, descriptorIndex);
                break;

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
        this.notifyAndWriteData(targetDevice._attachedSocket, this.constructDeviceDescriptor(targetDevice, descriptorIndex, setup.wLength));
    }
    
    /**
     * 
     * @param {SimulatedUsbDevice} targetDevice
     * @param {ParsedSetupBytes} setup
     * @param {number} descriptorIndex
     */
    handleGetConfigDescriptorPacket(targetDevice, setup, descriptorIndex) {
        this.notifyAndWriteData(targetDevice._attachedSocket, this.constructConfigDescriptor(targetDevice, descriptorIndex, setup.wLength, true));
    }
    
    /**
     * 
     * @param {SimulatedUsbDevice} targetDevice
     * @param {ParsedSetupBytes} setup
     * @param {number} descriptorIndex
     */
    handleGetStringDescriptorPacket(targetDevice, setup, descriptorIndex){
        throw new Error('Not Implemented');
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
        throw new Error('Not Implemented');
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
     * @param {ParsedSetupBytes} setup
     */
    handleSetInterfacePacket(targetDevice, setup) {
        throw new Error('Not Implemented');
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
     * @param {SubmitCommandBody} body
     */
    handleInterruptPacketBody(targetDevice, body) {
        if (body.transferBuffer.length) {
            throw new Error(`I don't know what to do with an INTERRUPT packet when it has a transferBuffer.`);
        } else if (body.isoPacketDescriptor.length) {
            throw new Error(`I don't know what to do with an INTERRUPT packet when it has an isoPacketDescriptor.`);
        } else {
            this.server.queueInterruptPacket(targetDevice, body);
        }
    }

    /**
     * 
     * @param {SimulatedUsbDevice} sender
     * @param {Buffer} data
     */
    handleDeviceInterrupt(sender, data) {
        let interrupt = this.server.dequeueInterruptPacket(sender);
        let response = this.constructInterruptResponse(interrupt, data);
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
            for (let versionNibble of versionSplit.reverse().map(Number)) {
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
                    var isoPacketDescriptor = Buffer.alloc(0);
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
        let defaultConfig = spec.configurations.find(config => !spec.bConfigurationValue || config.bConfigurationValue == spec.bConfigurationValue);
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
        let config = device.spec.configurations[index];

        let configDescriptor = Buffer.from(
            [
                requestedLength,
                lib.descriptorTypes.config,
                0, 0, // wTotalLength (2-bytes, to be written later)
                config.bNumInterfaces,
                config.bConfigurationValue,
                config.iConfiguration,
                this.encodeConfigAttributes(config.bmAttributes),
                config.bMaxPower,
            ]
        );

        if (!requestedLength) {
            configDescriptor.writeUInt8(configDescriptor.length);
        }

        if (includeInterfaceDescriptors) {
            for (let iface of config.interfaces) {
                configDescriptor = Buffer.concat(
                    [
                        configDescriptor,
                        this.constructInterfaceDescriptor(iface, true),
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
     * @param {SubmitCommandBody} interruptRequest
     * @param {Buffer} responseData
     */
    constructInterruptResponse(interruptRequest, responseData) {
        let iHeader = interruptRequest.header;
        return Buffer.concat(
            [
                lib.commands.USBIP_RET_SUBMIT,
                this.constructUsbipBasicHeader(iHeader.seqnum, 0, iHeader.direction, 0),
                this.constructStatusBytes(0),
                this.constructUInt32BE(responseData.length),
                Buffer.alloc(8), // start_frame and number_of_packets will both be zero because this is not an ISO transfer
                Buffer.alloc(4), // TODO: error_count; not sure how to handle this yet
                Buffer.alloc(8), // padding
                responseData,
            ]
        );
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

    /**
     * 
     * @param {SimulatedUsbDevice} device
     * @param {number} endpointNumberQuery
     */
    getEndpoint(device, endpointNumberQuery) {
        for (let config of device.spec.configurations) {
            if (config.bConfigurationValue == device.spec.bConfigurationValue) {
                for (let iface of config.interfaces) {
                    for (let endpoint of iface.endpoints) {
                        if (endpoint.bEndpointAddress.endpointNumber == endpointNumberQuery) {
                            return endpoint;
                        }
                    }
                }
            }
        }

        throw new Error(`The device's current configuration does not contain an endpoint numbered '${endpointNumberQuery}'`);
    }

    /**
     * Returns the new length of the interrupt queue for this device
     * @param {SimulatedUsbDevice} device
     * @param {SubmitCommandBody} interrupt
     */
    queueInterruptPacket(device, interrupt) {
        if (!interrupt) {
            throw new Error('interrupt cannot be null');
        } else {
            let q = this._interruptQMap.get(device);

            if (!q) {
                q = new Queue();
                this._interruptQMap.set(device, q);
            }

            return q.enqueue(interrupt);
        }
    }

    /**
     *
     * @param {SimulatedUsbDevice} device
     */
    dequeueInterruptPacket(device) {
        let q = this._interruptQMap.get(device);

        if (!q) {
            return null;
        } else {
            return q.dequeue();
        }
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
 * @property {number} bcdDevice
 * @property {string} bcdUSB USB specification version (Formatted such that version 2.1 is represented as '0.2.1.0')
 * @property {number} bDeviceClass
 * @property {number} bDeviceSubClass
 * @property {number} bDeviceProtocol
 * @property {8 | 16 | 32 | 64} bMaxPacketSize0 Maximum packet size for Endpoint zero
 * @property {number} bConfigurationValue
 * @property {number} iManufacturer
 * @property {number} iProduct
 * @property {number} iSerialNumber
 * @property {number} [bNumConfigurations]
 * @property {SimulatedUsbDeviceConfiguration[]} configurations
 * @property {string[]} [stringDescriptors]
 */

/**
 * @typedef SimulatedUsbDeviceConfiguration
 * @property {number} [bConfigurationValue]
 * @property {number | ConfigAttributes} bmAttributes
 * @property {number} bMaxPower in increments of 2mA (for example, if max power is 100mA, bMaxPower should be 50)
 * @property {number} [bNumInterfaces]
 * @property {SimulatedUsbDeviceInterface[]} [interfaces]
 * @property {number} iConfiguration
 */

/**
 * @typedef ConfigAttributes
 * @property {boolean} selfPowered
 * @property {boolean} remoteWakeup
 */

/**
 * @typedef SimulatedUsbDeviceInterface
 * @property {number} [bInterfaceNumber]
 * @property {number} bAlternateSetting
 * @property {number} bInterfaceClass
 * @property {number} bInterfaceSubClass
 * @property {number} bInterfaceProtocol
 * @property {number} [bNumEndpoints]
 * @property {SimulatedUsbDeviceEndpoint[]} [endpoints]
 * @property {number} iInterface
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
 * @property {number} [synchronisationType] ISO mode only
 * @property {number} [usageType] ISO mode only
 */

class SimulatedUsbDevice extends EventEmitter {
    /**
     * 
     * @param {SimulatedUsbDeviceSpec} spec
     */
    constructor(spec) {
        super();
        this.spec = spec;

        /** @type {net.Socket} */
        this._attachedSocket = null;
    }

    /**
     * 
     * @param {Buffer} data
     */
    interrupt(data) {
        this.emit('interrupt', data);
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
            console.log(`Wrote ${util.inspect(server._protocolLayer.parsePacket(data, { parseLeftoverData: true, parseSetupPackets: true }))}`);
        }
    });

    server.on('protocolError', console.error);

    let scannerDevice = new SimulatedUsbDevice({
        //busnum: 3,
        //devnum: 1,
        //path: '/sys/devices/simulation/usb3/3-1',
        //busid: '3-1',
        bcdDevice: 261,
        bcdUSB: '0', // TODO: don't know what version the scanner runs on
        idVendor: 1008,
        idProduct: 825,
        bDeviceClass: 2,
        bDeviceSubClass: 0,
        bDeviceProtocol: 0,
        bMaxPacketSize0: 8, // TODO: don't know what this number is for the scanner
        iManufacturer: 1,
        iProduct: 2,
        iSerialNumber: 0,
        bConfigurationValue: 0, // dont have example of this
        bNumConfigurations: 1,
        speed: 3,
        configurations: [
            
        ],
        stringDescriptors: [
            'English',
            'HP',
            'Barcode Scanner',
        ],
    });

    let mouseDevice = new SimulatedUsbDevice({
        bcdDevice: 0,
        bcdUSB: '2.0.0',
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
                bMaxPower: 50,
                bmAttributes: {
                    selfPowered: true,
                    remoteWakeup: true,
                },
                interfaces: [
                    {
                        iInterface: 4,
                        bInterfaceClass: 0x03, // HID
                        bInterfaceSubClass: 0x01,
                        bInterfaceProtocol: 0x02, // Mouse
                        bAlternateSetting: 0,
                        endpoints: [
                            {
                                bEndpointAddress: {
                                    direction: lib.directions.in,
                                },
                                bmAttributes: {
                                    transferType: lib.transferTypes.interrupt,
                                },
                                wMaxPacketSize: 8, 
                            },
                        ],
                    },
                ],
            },
        ],
        stringDescriptors: [
            'English',               // index 0
            'Dell',                  // index 1
            'Optical Wheel Mouse',   // index 2
            'Default Configuration', // index 3
            'Default Interface',     // index 4
        ],
    });

    //server.exportDevice(scannerDevice);
    server.exportDevice(mouseDevice);

    server.listen('0.0.0.0');

    //collectTestData();
}

function collectTestData() {
    let fs = require('fs');
    let proto = new UsbIpProtocolLayer();

    for (let key in require('./test_data.js').data) {
        fs.appendFileSync('test.txt', `${key} ${util.inspect(proto.parsePacket(Buffer.from(data[key]), { parseSetupPackets: true, parseLeftoverData: true }), false, Infinity)}`);
        fs.appendFileSync('test.txt', '-----------------------------------------------------------------------------------------------------------------------------------------------------------\r\n');
    }
}
