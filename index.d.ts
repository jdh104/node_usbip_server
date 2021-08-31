/// <reference types="node" />
export type UsbIpServerSimConfig = {
    version: string;
    simulatedBusNumber?: number | undefined;
    tcpOptions?: net.ServerOpts | undefined;
    eventEmitterOptions?: EventEmitterOptions | undefined;
    /**
     * Must be an absolute posix path
     */
    devicesDirectory?: string | undefined;
};
export type EventEmitterOptions = {
    captureRejections?: boolean | undefined;
};
export type UsbDeviceFindPredicate = (device: SimulatedUsbDevice) => boolean;
export type UsbIpParsedPacket = {
    error?: Error | undefined;
    version: string;
    commandCode: string;
    status?: number | undefined;
    /**
     * type depends on `commandCode`
     */
    body: DevListRequestBody | DevListResponseBody | ImportRequestBody | ImportResponseBody | SubmitCommandBody | SubmitResponseBody | UnlinkCommandBody | UnlinkResponseBody;
};
export type DevListRequestBody = {
    status: number;
};
export type DevListResponseBody = {
    status: number;
    deviceListLength: number;
    deviceList: SimulatedUsbDeviceSpec[];
};
export type ImportRequestBody = {
    status: number;
    busid: string;
};
export type ImportResponseBody = {
    status: number;
    device: SimulatedUsbDeviceSpec;
};
export type UsbipBasicHeader = {
    seqnum: number;
    /**
     * for server, this shall be set to 0
     */
    devid: number;
    /**
     * 0: USBIP_DIR_OUT, 1: USBIP_DIR_IN; for server, this shall be 0
     */
    direction: number;
    endpoint: number;
};
export type SubmitCommandBody = {
    header: UsbipBasicHeader;
    transferFlags: number;
    transferBufferLength: number;
    /**
     * shall be set to 0 if not ISO transfer
     */
    startFrame: number;
    /**
     * shall be set to 0xffffffff if not ISO transfer
     */
    numberOfPackets: number;
    interval: number;
    setup: Buffer | ParsedSetupBytes;
    transferBuffer: Buffer;
    isoPacketDescriptor: Buffer;
    leftoverData?: Buffer | UsbIpParsedPacket | undefined;
};
export type SubmitResponseBody = {
    header: UsbipBasicHeader;
    status: number;
    actualLength: number;
    startFrame: number;
    numberOfPackets: number;
    errorCount: number;
    transferBuffer: Buffer;
    isoPacketDescriptor: Buffer;
};
export type UnlinkCommandBody = {
    header: UsbipBasicHeader;
    unlinkSeqNum: number;
};
export type UnlinkResponseBody = {
    header: UsbipBasicHeader;
    status: number;
};
export type ParsedSetupBytes = {
    bmRequestType: BmRequestType;
    bRequest: number;
    wValue: number;
    wIndex: number;
    wLength: number;
};
export type BmRequestType = {
    direction: number;
    rType: number;
    recipient: number;
};
export type SimulatedUsbDeviceSpec = {
    /**
     * Will be automatically set by server simulator when exported (if not present)
     */
    path?: string | undefined;
    /**
     * Will be automatically set by server simulator when exported (if not present)
     */
    busid?: string | undefined;
    /**
     * Will be automatically set by server simulator when exported (if not present)
     */
    busnum?: number | undefined;
    /**
     * Will be automatically set by server simulator when exported (if not present)
     */
    devnum?: number | undefined;
    speed: number;
    idVendor: number;
    idProduct: number;
    /**
     * device revision number
     */
    bcdDevice: number;
    /**
     * USB specification version (Formatted such that version 2.1 is represented as '0.2.1.0')
     */
    bcdUSB: string;
    bDeviceClass: number;
    bDeviceSubClass: number;
    bDeviceProtocol: number;
    /**
     * Maximum packet size for Endpoint zero
     */
    bMaxPacketSize0: 8 | 16 | 32 | 64;
    bConfigurationValue?: number | undefined;
    iManufacturer?: number | undefined;
    iProduct?: number | undefined;
    iSerialNumber?: number | undefined;
    bNumConfigurations?: number | undefined;
    configurations: SimulatedUsbDeviceConfiguration[];
    supportedLangs?: number[] | undefined;
    stringDescriptors?: string[] | undefined;
    endpointShortcutMap?: SimulatedUsbDeviceEndpoint[] | undefined;
};
export type SimulatedUsbDeviceConfiguration = {
    bConfigurationValue?: number | undefined;
    bmAttributes: number | ConfigAttributes;
    /**
     * in increments of 2mA (for example, if max power is 100mA, bMaxPower should be 50)
     */
    bMaxPower: number;
    bNumInterfaces?: number | undefined;
    interfaces?: SimulatedUsbDeviceInterface[] | undefined;
    iConfiguration: number;
    /**
     * Represents the "currently selected" interface (not part of spec apparently)
     */
    _bInterfaceNumber?: number | undefined;
};
export type ConfigAttributes = {
    selfPowered: boolean;
    remoteWakeup: boolean;
};
export type SimulatedUsbDeviceInterface = {
    bInterfaceNumber?: number | undefined;
    bAlternateSetting?: number | undefined;
    bInterfaceClass: number;
    bInterfaceSubClass: number;
    bInterfaceProtocol: number;
    communicationsDescriptors?: Buffer[] | undefined;
    /**
     * Only necessary if device is class HID
     */
    hidDescriptor?: SimulatedUsbDeviceHidDescriptor | undefined;
    bNumEndpoints?: number | undefined;
    endpoints?: SimulatedUsbDeviceEndpoint[] | undefined;
    iInterface?: number | undefined;
    _lineCoding?: CdcLineCoding | undefined;
    _controlLineState?: Buffer | undefined;
    _isIdle?: boolean | undefined;
};
export type CdcLineCoding = {
    dwDTERate: number;
    bCharFormat: number;
    bParityType: number;
    bDataBits: number;
};
export type SimulatedUsbDeviceHidDescriptor = {
    bcdHID: number;
    bCountryCode?: number | undefined;
    wDescriptorLength?: number | undefined;
    report?: any;
    preCompiledReport?: Buffer | undefined;
};
/**
 * Not supported yet (why would we ever?)
 */
export type HidReportDescriptorReport = any;
export type SimulatedUsbDeviceEndpoint = {
    bEndpointAddress: EndpointAddress;
    bmAttributes: EndpointAttributes;
    wMaxPacketSize: number;
    bInterval: number;
};
export type EndpointAddress = {
    endpointNumber?: number | undefined;
    direction: 0 | 1;
};
export type EndpointAttributes = {
    transferType: number;
    /**
     * required only for isochronous transferType
     */
    synchronisationType?: number | undefined;
    /**
     * required only for isochronous transferType
     */
    usageType?: number | undefined;
};
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
export class UsbIpServerSim extends EventEmitter {
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
    constructor(config: UsbIpServerSimConfig);
    _server: UsbIpServer;
    _protocolLayer: UsbIpProtocolLayer;
    /**
     *
     * @param {SimulatedUsbDevice} device
     */
    exportDevice(device: SimulatedUsbDevice): SimulatedUsbDevice;
    /**
     * Ensure required properties exist, and assign values which were left out by the user.
     * @param {SimulatedUsbDeviceSpec} spec
     * @param {number} defaultDeviceNumber
     */
    _normalizeDeviceSpec(spec: SimulatedUsbDeviceSpec, defaultDeviceNumber: number): void;
    /**
     * Ensure required properties exist, and assign values which were left out by the user.
     * @param {SimulatedUsbDeviceConfiguration} config
     * @param {number} defaultConfigNumber
     * @param {SimulatedUsbDeviceSpec} parentSpec
     */
    _normalizeDeviceConfig(config: SimulatedUsbDeviceConfiguration, defaultConfigNumber: number, parentSpec: SimulatedUsbDeviceSpec): void;
    /**
     * Ensure required properties exist, and assign values which were left out by the user.
     * @param {SimulatedUsbDeviceInterface} iface
     * @param {number} defaultIfaceNumber
     * @param {SimulatedUsbDeviceConfiguration} parentConfig
     * @param {SimulatedUsbDeviceSpec} parentSpec
     */
    _normalizeDeviceInterface(iface: SimulatedUsbDeviceInterface, defaultIfaceNumber: number, parentConfig: SimulatedUsbDeviceConfiguration, parentSpec: SimulatedUsbDeviceSpec): void;
    /**
     * Ensure required properties exist, and assign values which were left out by the user.
     * @param {SimulatedUsbDeviceEndpoint} endpoint
     * @param {number} defaultEndpointNumber
     * @param {SimulatedUsbDeviceInterface} parentInterface
     * @param {SimulatedUsbDeviceConfiguration} parentConfig
     * @param {SimulatedUsbDeviceSpec} parentSpec
     */
    _normalizeDeviceEndpoint(endpoint: SimulatedUsbDeviceEndpoint, defaultEndpointNumber: number, parentInterface: SimulatedUsbDeviceInterface, parentConfig: SimulatedUsbDeviceConfiguration, parentSpec: SimulatedUsbDeviceSpec): void;
    /**
     *
     * @param {number | string | SimulatedUsbDevice} device Can be index, path, busid, or the device object itself
     * @returns {SimulatedUsbDevice}
     */
    removeDevice(device: number | string | SimulatedUsbDevice): SimulatedUsbDevice;
    removeAllDevices(): SimulatedUsbDevice[];
    /**
     *
     * @param {string} address
     * @param {number} [port] Default: 3240
     */
    listen(address: string, port?: number | undefined): UsbIpServerSim;
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
export class SimulatedUsbDevice extends EventEmitter {
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
    constructor(spec: SimulatedUsbDeviceSpec);
    spec: SimulatedUsbDeviceSpec;
    /** @type {net.Socket} */
    _attachedSocket: net.Socket;
    /**
     * Pending-Bulk-In-Packets
     * @type {Queue<SubmitCommandBody>}
     */
    _pbips: Queue<SubmitCommandBody>;
    /**
     * Pending-Bulk-Out-Packets
     * @type {Queue<Buffer>}
     */
    _pbops: Queue<Buffer>;
    /**
     * Pending-Interrupt-In-Packets
     * @type {Queue<SubmitCommandBody>}
     */
    _piips: Queue<SubmitCommandBody>;
    /**
     * Pending-Interrupt-Out-Packets
     * @type {Queue<Buffer>}
     */
    _piops: Queue<Buffer>;
    /**
     *
     * @param {number} [configQuery]
     * @returns {SimulatedUsbDeviceConfiguration}
     */
    _findConfig(configQuery?: number | undefined): SimulatedUsbDeviceConfiguration;
    /**
     *
     * @param {SimulatedUsbDeviceConfiguration} [config]
     * @param {number} [ifaceQuery]
     * @returns {SimulatedUsbDeviceInterface}
     */
    _findIface(config?: SimulatedUsbDeviceConfiguration | undefined, ifaceQuery?: number | undefined): SimulatedUsbDeviceInterface;
    /**
     *
     * @param {SimulatedUsbDeviceInterface} iface
     * @param {number} endpointNumberQuery
     * @returns {SimulatedUsbDeviceEndpoint}
     */
    _findEndpoint(iface: SimulatedUsbDeviceInterface, endpointNumberQuery: number): SimulatedUsbDeviceEndpoint;
    /**
     *
     * @param {Buffer} data
     * @fires SimulatedUsbDevice#bulkToHost
     */
    bulk(data: Buffer): void;
    /**
     *
     * @param {Buffer} data
     * @fires SimulatedUsbDevice#interrupt
     */
    interrupt(data: Buffer): void;
    [util.inspect.custom](depth: any, opts: any): string;
}
import lib = require("./lib.js");
/** */
declare class UsbIpProtocolLayer extends EventEmitter {
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
    constructor(serverToControl: UsbIpServer, version?: string | undefined);
    versionString: string | undefined;
    encodedVersionNumber: number;
    server: UsbIpServer;
    /**
     *
     * @param {Error} err
     * @fires UsbIpProtocolLayer#error
     */
    error(err: Error): void;
    /**
     *
     * @param {Buffer} incomingData
     * @param {net.Socket} socket
     */
    handle(incomingData: Buffer, socket: net.Socket): void;
    /**
     *
     * @param {SimulatedUsbDevice} device
     */
    notifyRemoved(device: SimulatedUsbDevice): void;
    /**
     *
     * @param {net.Socket} socket
     * @param {Buffer} data
     * @fires UsbIpProtocolLayer#write
     */
    notifyAndWriteData(socket: net.Socket, data: Buffer): boolean;
    /**
     *
     * @param {SubmitResponseBody} packet
     */
    constructSubmitResponsePacket(packet: SubmitResponseBody): Buffer;
    /**
     *
     * @param {SimulatedUsbDevice} targetDevice
     * @param {SubmitCommandBody} body
     */
    constructControlPacketResponse(targetDevice: SimulatedUsbDevice, body: SubmitCommandBody): Buffer;
    /**
     *
     * @param {SimulatedUsbDevice} targetDevice
     * @param {SubmitCommandBody} body
     */
    handleControlPacketBody(targetDevice: SimulatedUsbDevice, body: SubmitCommandBody): void | Buffer;
    /**
     *
     * @param {SimulatedUsbDevice} targetDevice
     * @param {SubmitCommandBody} body
     * @param {ParsedSetupBytes} setup
     */
    handleStandardControlPacketBody(targetDevice: SimulatedUsbDevice, body: SubmitCommandBody, setup: ParsedSetupBytes): void | Buffer;
    /**
     *
     * @param {SimulatedUsbDevice} targetDevice
     * @param {SubmitCommandBody} body
     * @param {ParsedSetupBytes} setup
     */
    handleClassControlPacketBody(targetDevice: SimulatedUsbDevice, body: SubmitCommandBody, setup: ParsedSetupBytes): void | Buffer;
    /**
     *
     * @param {SimulatedUsbDevice} targetDevice
     * @param {SubmitCommandBody} body
     * @param {ParsedSetupBytes} setup
     */
    handleClassDeviceControlPacketBody(targetDevice: SimulatedUsbDevice, body: SubmitCommandBody, setup: ParsedSetupBytes): void;
    /**
     *
     * @param {SimulatedUsbDevice} targetDevice
     * @param {SubmitCommandBody} body
     * @param {ParsedSetupBytes} setup
     */
    handleClassInterfaceControlPacketBody(targetDevice: SimulatedUsbDevice, body: SubmitCommandBody, setup: ParsedSetupBytes): Buffer;
    /**
     *
     * @param {SimulatedUsbDevice} targetDevice
     * @param {SubmitCommandBody} body
     * @param {ParsedSetupBytes} setup
     */
    handleClassEndpointControlPacketBody(targetDevice: SimulatedUsbDevice, body: SubmitCommandBody, setup: ParsedSetupBytes): void;
    /**
     *
     * @param {SimulatedUsbDevice} targetDevice
     * @param {SubmitCommandBody} body
     * @param {ParsedSetupBytes} setup
     */
    handleClassOtherControlPacketBody(targetDevice: SimulatedUsbDevice, body: SubmitCommandBody, setup: ParsedSetupBytes): void;
    /**
     *
     * @param {SimulatedUsbDevice} targetDevice
     * @param {SubmitCommandBody} body
     * @param {ParsedSetupBytes} setup
     */
    handleVendorControlPacketBody(targetDevice: SimulatedUsbDevice, body: SubmitCommandBody, setup: ParsedSetupBytes): void;
    /**
     *
     * @param {SimulatedUsbDevice} targetDevice
     * @param {SubmitCommandBody} body
     * @param {ParsedSetupBytes} setup
     */
    handleStandardDeviceControlPacketBody(targetDevice: SimulatedUsbDevice, body: SubmitCommandBody, setup: ParsedSetupBytes): void | Buffer;
    /**
     *
     * @param {SimulatedUsbDevice} targetDevice
     * @param {SubmitCommandBody} body
     * @param {ParsedSetupBytes} setup
     */
    handleStandardInterfaceControlPacketBody(targetDevice: SimulatedUsbDevice, body: SubmitCommandBody, setup: ParsedSetupBytes): void | Buffer;
    /**
     *
     * @param {SimulatedUsbDevice} targetDevice
     * @param {SubmitCommandBody} body
     * @param {ParsedSetupBytes} setup
     */
    handleStandardEndpointControlPacketBody(targetDevice: SimulatedUsbDevice, body: SubmitCommandBody, setup: ParsedSetupBytes): void;
    /**
     *
     * @param {SimulatedUsbDevice} targetDevice
     * @param {SubmitCommandBody} body
     * @param {ParsedSetupBytes} setup
     */
    handleStandardOtherControlPacketBody(targetDevice: SimulatedUsbDevice, body: SubmitCommandBody, setup: ParsedSetupBytes): void;
    /**
     *
     * @param {SimulatedUsbDevice} targetDevice
     * @param {ParsedSetupBytes} setup
     */
    handleDeviceGetStatusPacket(targetDevice: SimulatedUsbDevice, setup: ParsedSetupBytes): void;
    /**
     *
     * @param {SimulatedUsbDevice} targetDevice
     * @param {ParsedSetupBytes} setup
     */
    handleInterfaceGetStatusPacket(targetDevice: SimulatedUsbDevice, setup: ParsedSetupBytes): void;
    /**
     *
     * @param {SimulatedUsbDevice} targetDevice
     * @param {ParsedSetupBytes} setup
     */
    handleDeviceClearFeaturePacket(targetDevice: SimulatedUsbDevice, setup: ParsedSetupBytes): void;
    /**
     *
     * @param {SimulatedUsbDevice} targetDevice
     * @param {ParsedSetupBytes} setup
     */
    handleInterfaceClearFeaturePacket(targetDevice: SimulatedUsbDevice, setup: ParsedSetupBytes): void;
    /**
     *
     * @param {SimulatedUsbDevice} targetDevice
     * @param {ParsedSetupBytes} setup
     */
    handleDeviceSetFeaturePacket(targetDevice: SimulatedUsbDevice, setup: ParsedSetupBytes): void;
    /**
     *
     * @param {SimulatedUsbDevice} targetDevice
     * @param {ParsedSetupBytes} setup
     */
    handleInterfaceSetFeaturePacket(targetDevice: SimulatedUsbDevice, setup: ParsedSetupBytes): void;
    /**
     *
     * @param {SimulatedUsbDevice} targetDevice
     * @param {ParsedSetupBytes} setup
     */
    handleSetAddressPacket(targetDevice: SimulatedUsbDevice, setup: ParsedSetupBytes): void;
    /**
     * Standard device request only (type = standard, recipient = device)
     * @param {SimulatedUsbDevice} targetDevice
     * @param {ParsedSetupBytes} setup
     */
    handleGetDescriptorPacket(targetDevice: SimulatedUsbDevice, setup: ParsedSetupBytes): void | Buffer;
    /**
     *
     * @param {SimulatedUsbDevice} targetDevice
     * @param {ParsedSetupBytes} setup
     * @param {number} descriptorIndex
     */
    handleGetDeviceDescriptorPacket(targetDevice: SimulatedUsbDevice, setup: ParsedSetupBytes, descriptorIndex: number): Buffer;
    /**
     *
     * @param {SimulatedUsbDevice} targetDevice
     * @param {ParsedSetupBytes} setup
     * @param {number} descriptorIndex
     */
    handleGetConfigDescriptorPacket(targetDevice: SimulatedUsbDevice, setup: ParsedSetupBytes, descriptorIndex: number): Buffer;
    /**
     *
     * @param {SimulatedUsbDevice} targetDevice
     * @param {ParsedSetupBytes} setup
     * @param {number} descriptorIndex
     */
    handleGetStringDescriptorPacket(targetDevice: SimulatedUsbDevice, setup: ParsedSetupBytes, descriptorIndex: number): Buffer;
    /**
     *
     * @param {number[]} supportedLangs
     */
    constructSupportedLangsDescriptor(supportedLangs: number[]): Buffer;
    /**
     *
     * @param {string} descriptor
     */
    constructStringDescriptorFromString(descriptor: string): Buffer;
    /**
     *
     * @param {Buffer} descriptorBytes
     */
    constructStringDescriptor(descriptorBytes: Buffer): Buffer;
    /**
     *
     * @param {SimulatedUsbDevice} targetDevice
     * @param {ParsedSetupBytes} setup
     * @param {number} descriptorIndex
     */
    handleGetInterfaceDescriptorPacket(targetDevice: SimulatedUsbDevice, setup: ParsedSetupBytes, descriptorIndex: number): void;
    /**
     *
     * @param {SimulatedUsbDevice} targetDevice
     * @param {ParsedSetupBytes} setup
     * @param {number} descriptorIndex
     */
    handleGetEndpointDescriptorPacket(targetDevice: SimulatedUsbDevice, setup: ParsedSetupBytes, descriptorIndex: number): void;
    /**
     *
     * @param {SimulatedUsbDevice} targetDevice
     * @param {ParsedSetupBytes} setup
     */
    handleSetDescriptorPacket(targetDevice: SimulatedUsbDevice, setup: ParsedSetupBytes): void;
    /**
     *
     * @param {SimulatedUsbDevice} targetDevice
     * @param {ParsedSetupBytes} setup
     */
    handleGetConfigurationPacket(targetDevice: SimulatedUsbDevice, setup: ParsedSetupBytes): void;
    /**
     *
     * @param {SimulatedUsbDevice} targetDevice
     * @param {ParsedSetupBytes} setup
     */
    handleSetConfigurationPacket(targetDevice: SimulatedUsbDevice, setup: ParsedSetupBytes): Buffer;
    /**
     *
     * @param {SimulatedUsbDevice} targetDevice
     * @param {ParsedSetupBytes} setup
     */
    handleGetInterfacePacket(targetDevice: SimulatedUsbDevice, setup: ParsedSetupBytes): void;
    /**
     *
     * @param {SimulatedUsbDevice} targetDevice
     * @param {SimulatedUsbDeviceInterface} iface
     * @param {ParsedSetupBytes} setup
     * @param {Buffer} payload
     */
    handleCdcSetLineCodingPacket(targetDevice: SimulatedUsbDevice, iface: SimulatedUsbDeviceInterface, setup: ParsedSetupBytes, payload: Buffer): Buffer;
    /**
     *
     * @param {Buffer} coding
     * @returns {CdcLineCoding}
     */
    readCdcLineCoding(coding: Buffer): CdcLineCoding;
    /**
     *
     * @param {SimulatedUsbDevice} targetDevice
     * @param {SimulatedUsbDeviceInterface} iface
     * @param {ParsedSetupBytes} setup
     * @param {Buffer} payload
     */
    handleCdcSetControlLineStatePacket(targetDevice: SimulatedUsbDevice, iface: SimulatedUsbDeviceInterface, setup: ParsedSetupBytes, payload: Buffer): Buffer;
    /**
     *
     * @param {SimulatedUsbDevice} targetDevice
     * @param {SimulatedUsbDeviceInterface} iface
     * @param {ParsedSetupBytes} setup
     */
    handleHidSetIdlePacket(targetDevice: SimulatedUsbDevice, iface: SimulatedUsbDeviceInterface, setup: ParsedSetupBytes): Buffer;
    /**
     *
     * @param {SimulatedUsbDevice} targetDevice
     * @param {ParsedSetupBytes} setup
     */
    handleSetInterfacePacket(targetDevice: SimulatedUsbDevice, setup: ParsedSetupBytes): Buffer;
    /**
     *
     * @param {SimulatedUsbDeviceInterface} iface
     */
    handleGetHidReportDescriptorPacket(iface: SimulatedUsbDeviceInterface): Buffer;
    /**
     *
     * @param {SimulatedUsbDevice} targetDevice
     * @param {ParsedSetupBytes} setup
     */
    handleSynchFramePacket(targetDevice: SimulatedUsbDevice, setup: ParsedSetupBytes): void;
    /**
     *
     * @param {SimulatedUsbDevice} targetDevice
     * @param {SubmitCommandBody} bulk
     */
    handleBulkPacketBody(targetDevice: SimulatedUsbDevice, bulk: SubmitCommandBody): void;
    /**
     *
     * @param {SimulatedUsbDevice} targetDevice
     * @param {SubmitCommandBody} interrupt
     */
    handleInterruptPacketBody(targetDevice: SimulatedUsbDevice, interrupt: SubmitCommandBody): void;
    /**
     *
     * @param {SimulatedUsbDevice} sender
     * @param {SubmitCommandBody} bulkRequest
     * @param {Buffer} data
     */
    handleDeviceBulkData(sender: SimulatedUsbDevice, bulkRequest: SubmitCommandBody, data: Buffer): void;
    /**
     *
     * @param {SimulatedUsbDevice} sender
     * @param {SubmitCommandBody} interrupt
     * @param {Buffer} data
     */
    handleDeviceInterrupt(sender: SimulatedUsbDevice, interrupt: SubmitCommandBody, data: Buffer): void;
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
    parsePacket(packet: Buffer, options?: {
        parseLeftoverData: boolean;
        parseSetupPackets: boolean;
    } | undefined): UsbIpParsedPacket;
    /**
     *
     * @param {number} uint16
     */
    constructUInt16BE(uint16: number): Buffer;
    /**
     *
     * @param {number} uint32
     */
    constructUInt32BE(uint32: number): Buffer;
    /**
     *
     * @param {string} str
     */
    constructPaddedStringBuffer(str: string, desiredLength: any): Buffer;
    /**
     *
     * @param {Buffer} buf
     */
    readPaddedStringBuffer(buf: Buffer): string;
    /**
     *
     * @param {number} serverVersion
     * @param {SimulatedUsbDevice[]} deviceList
     */
    constructDeviceListResponse(serverVersion: number, deviceList: SimulatedUsbDevice[]): Buffer;
    /**
     *
     * @param {Buffer} deviceList
     */
    readDeviceList(deviceList: Buffer): any;
    /**
     *
     * @param {Buffer} deviceDescription
     * @param {boolean} [allowEmptyDescription]
     * @returns {SimulatedUsbDeviceSpec}
     */
    readDeviceDescription(deviceDescription: Buffer, allowEmptyDescription?: boolean | undefined): SimulatedUsbDeviceSpec;
    /**
     *
     * @param {number} serverVersion
     * @param {SimulatedUsbDevice} deviceToImport
     * @param {boolean} [importSucceeded]
     */
    constructImportResponse(serverVersion: number, deviceToImport: SimulatedUsbDevice, importSucceeded?: boolean | undefined): Buffer;
    /**
     *
     * @param {number} serverVersion
     * @param {Buffer} replyCode
     * @param {number} [status]
     */
    constructOperationHeaderBytes(serverVersion: number, replyCode: Buffer, status?: number | undefined): Buffer;
    /**
     *
     * @param {number} version
     */
    constructVersionBytes(version: number): Buffer;
    /**
     *
     * @param {number} version
     */
    decodeVersion(version: number): string;
    /**
     *
     * @param {string} version
     */
    encodeVersion(version: string): number;
    /**
     *
     * @param {Buffer} version
     */
    readVersion(version: Buffer): string;
    /**
     *
     * @param {number} replyCode
     */
    constructReplyCodeBytes(replyCode: number): Buffer;
    /**
     *
     * @param {Buffer} opCodeBytes
     */
    readOperationCode(opCodeBytes: Buffer): string;
    /**
     *
     * @param {Buffer} commandCodeBytes
     */
    readCommandCode(commandCodeBytes: Buffer): string;
    /**
     *
     * @param {string} version
     * @param {string} operation
     * @param {Buffer} body
     */
    readOperationBody(version: string, operation: string, body: Buffer): DevListRequestBody;
    /**
     *
     * @param {string} command
     * @param {Buffer} body
     * @param {PacketParseOptions} [options]
     */
    readCommandBody(command: string, body: Buffer, options?: {
        parseLeftoverData: boolean;
        parseSetupPackets: boolean;
    } | undefined): SubmitCommandBody | UnlinkCommandBody | UnlinkResponseBody;
    /**
     *
     * @param {Buffer} body
     * @returns {DevListRequestBody}
     */
    readReqDevlistBody(body: Buffer): DevListRequestBody;
    /**
     *
     * @param {Buffer} body
     * @returns {DevListResponseBody}
     */
    readRepDevlistBody(body: Buffer): DevListResponseBody;
    /**
     *
     * @param {Buffer} body
     * @returns {ImportRequestBody}
     */
    readReqImportBody(body: Buffer): ImportRequestBody;
    /**
     *
     * @param {Buffer} body
     * @returns {ImportResponseBody}
     */
    readRepImportBody(body: Buffer): ImportResponseBody;
    /**
     *
     * @param {Buffer} body
     * @param {PacketParseOptions} [options]
     * @returns {SubmitCommandBody}
     */
    readCmdSubmitBody(body: Buffer, options?: {
        parseLeftoverData: boolean;
        parseSetupPackets: boolean;
    } | undefined): SubmitCommandBody;
    /**
     *
     * @param {Buffer} body
     * @returns {SubmitResponseBody}
     */
    readRetSubmitBody(body: Buffer): SubmitResponseBody;
    /**
     *
     * @param {Buffer} body
     * @returns {UnlinkCommandBody}
     */
    readCmdUnlinkBody(body: Buffer): UnlinkCommandBody;
    /**
     *
     * @param {Buffer} body
     * @returns {UnlinkResponseBody}
     */
    readRetUnlinkBody(body: Buffer): UnlinkResponseBody;
    /**
     *
     * @param {number} seqnum
     * @param {number} devid
     * @param {number} direction
     * @param {number} endpoint
     */
    constructUsbipBasicHeader(seqnum: number, devid: number, direction: number, endpoint: number): Buffer;
    /**
     * // NOTE: that official USBIP documentation includes the 'command' within the packets which
     * // use `usbip_header_basic`, but our parsing logic does not; instead, the `usbip_header_basic`
     * // is 16 bytes long, beginning at the seqnum field. This is because when taking any arbitrary
     * // buffer and deciding what command it represents, there is no way to distinguish between the
     * // "OP" commands and the "USBIP" commands without extra context.
     * @param {Buffer} header
     * @returns {UsbipBasicHeader}
     */
    readUsbipBasicHeader(header: Buffer): UsbipBasicHeader;
    /**
     * This format is defined by USB, _not_ usbip; meaning Little-Endian is used for multi-byte encoding
     * @param {Buffer} setup
     * @returns {ParsedSetupBytes}
     */
    readSetupBytes(setup: Buffer): ParsedSetupBytes;
    /**
     *
     * @param {number} bmRequestType 8-bit mask
     * @returns {BmRequestType}
     */
    readBmRequestType(bmRequestType: number): BmRequestType;
    /**
     *
     * @param {number} status
     */
    constructStatusBytes(status: number): Buffer;
    /**
     *
     * @param {number} length
     */
    constructDeviceListLength(length: number): Buffer;
    /**
     *
     * @param {Buffer} length
     */
    readDeviceListLength(length: Buffer): number;
    /**
     * Protocol: USBIP
     * @param {SimulatedUsbDevice} device
     * @param {boolean} [includeInterfaceDescriptions] Default: false
     */
    constructDeviceDescription(device: SimulatedUsbDevice, includeInterfaceDescriptions?: boolean | undefined): Buffer;
    /**
     * Protocol: USB
     * @param {SimulatedUsbDevice} device
     * @param {number} index
     * @param {number} [requestedLength]
     */
    constructDeviceDescriptor(device: SimulatedUsbDevice, index: number, requestedLength?: number | undefined): Buffer;
    /**
     * Protocol: USB
     * @param {SimulatedUsbDevice} device
     * @param {number} index
     * @param {number} [requestedLength]
     * @param {boolean} [includeInterfaceDescriptors]
     */
    constructConfigDescriptor(device: SimulatedUsbDevice, index: number, requestedLength?: number | undefined, includeInterfaceDescriptors?: boolean | undefined): Buffer;
    /**
     *
     * @param {ConfigAttributes} attributes
     */
    encodeConfigAttributes(attributes: ConfigAttributes): number;
    /**
     *
     * @param {SimulatedUsbDeviceInterface} iface
     */
    constructDeviceInterfaceDescription(iface: SimulatedUsbDeviceInterface): Buffer;
    /**
     *
     * @param {Buffer} interfaceList
     * @returns {Generator<SimulatedUsbDeviceInterfaceSpec, void, unknown>}
     */
    readInterfaceList(interfaceList: Buffer): Generator<any, void, unknown>;
    /**
     *
     * @param {SimulatedUsbDeviceInterface} iface
     * @param {number} requestedLength
     * @param {boolean} includeEndpointDescriptors
     */
    constructInterfaceDescriptor(iface: SimulatedUsbDeviceInterface, requestedLength: number, includeEndpointDescriptors: boolean): Buffer;
    /**
     *
     * @param {SimulatedUsbDeviceHidDescriptor} hidDescriptor
     */
    constructHidDescriptor(hidDescriptor: SimulatedUsbDeviceHidDescriptor): Buffer;
    /**
     *
     * @param {SimulatedUsbDeviceEndpoint} endpoint
     */
    constructEndpointDescriptor(endpoint: SimulatedUsbDeviceEndpoint): Buffer;
    /**
     *
     * @param {EndpointAddress} address
     */
    encodeEndpointAddress(address: EndpointAddress): number;
    /**
     *
     * @param {EndpointAttributes} attributes
     */
    encodeEndpointAttributes(attributes: EndpointAttributes): number;
    /**
     *
     * @param {string} path
     */
    constructPathBytes(path: string): Buffer;
    /**
     *
     * @param {string} path
     */
    constructBusId(busId: any): Buffer;
    /**
     *
     * @param {Buffer} busId
     */
    readBusId(busId: Buffer): string;
    /**
     *
     * @param {number} busNum
     */
    constructBusNum(busNum: number): Buffer;
    /**
     *
     * @param {number} devNum
     */
    constructDevNum(devNum: number): Buffer;
    /**
     *
     * @param {number} speed
     */
    constructSpeed(speed: number): Buffer;
    /**
     *
     * @param {number} idVendor
     */
    constructVendorId(idVendor: number): Buffer;
    /**
     *
     * @param {number} idProduct
     */
    constructProductId(idProduct: number): Buffer;
    /**
     *
     * @param {number} bcdDevice
     */
    constructDeviceBcd(bcdDevice: number): Buffer;
    /**
     *
     * @param {SubmitCommandBody} reqBody
     * @param {Buffer} transferBuffer
     */
    constructRetSubmitPacket(reqBody: SubmitCommandBody, transferBuffer: Buffer): Buffer;
    /**
     *
     * @param {SubmitCommandBody} bulkRequest
     * @param {Buffer} bData
     */
    constructBulkResponse(bulkRequest: SubmitCommandBody, bData: Buffer): Buffer;
    /**
     *
     * @param {SubmitCommandBody} interruptRequest
     * @param {Buffer} iData
     */
    constructInterruptResponse(interruptRequest: SubmitCommandBody, iData: Buffer): Buffer;
}
/** */
declare class UsbIpServer extends net.Server {
    /**
     *
     * @param {net.ServerOpts} tcpOptions
     * @param {string} [devicesDirectory]
     * @param {number} [busNumber]
     */
    constructor(tcpOptions: net.ServerOpts, devicesDirectory?: string | undefined, busNumber?: number | undefined);
    busNumber: number;
    devicesDirectory: string;
    /** @type {SimulatedUsbDevice[]} */
    devices: SimulatedUsbDevice[];
    /** @type {Map<SimulatedUsbDevice, Queue<SubmitCommandBody>>} */
    _interruptQMap: Map<SimulatedUsbDevice, Queue<SubmitCommandBody>>;
    enumerateDevices(): Generator<SimulatedUsbDevice, void, unknown>;
    getEmptyIndexes(): Generator<number, void, unknown>;
    /**
     *
     * @param {string | SimulatedUsbDevice} query path, busid, or SimulatedUsbDevice
     * @returns {number} index of device queried, or -1 if no result could be found
     */
    findDeviceIndex(query: string | SimulatedUsbDevice): number;
    /**
     *
     * @param {UsbDeviceFindPredicate} queryFunc
     */
    getDeviceWith(queryFunc: UsbDeviceFindPredicate): SimulatedUsbDevice | null;
    /**
     *
     * @param {string} pathQuery
     */
    getDeviceByPath(pathQuery: string): SimulatedUsbDevice | null;
    /**
     *
     * @param {string} busIdQuery
     */
    getDeviceByBusId(busIdQuery: string): SimulatedUsbDevice | null;
    /**
     *
     * @param {number} devIdQuery
     */
    getDeviceByDevId(devIdQuery: number): SimulatedUsbDevice | null;
}
import net = require("net");
import { EventEmitter } from "events";
import { Queue } from "./queue.js";
import util = require("util");
export declare namespace usbIpInternals {
    export { lib };
    export { UsbIpProtocolLayer };
    export { UsbIpServer };
}
export {};
