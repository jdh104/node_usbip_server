declare const _exports: UsbIpLexicon;
export = _exports;
declare class UsbIpLexicon {
    commands: UsbIpCommands;
    directions: UsbIpDirections;
    transferTypes: UsbTransferTypes;
    bmRequestTypes: BmRequestTypes;
    bRequests: BRequests;
    descriptorTypes: DescriptorTypes;
    interfaceClasses: InterfaceClasses;
    parity: Parities;
    stopBits: StopBits;
    errorCodes: ErrorCodes;
}
declare class UsbIpCommands {
    /** (0x8005) Retrieve the list of exported USB devices. */
    OP_REQ_DEVLIST: Buffer;
    /** (0x0005) Reply with the list of exported USB devices. */
    OP_REP_DEVLIST: Buffer;
    /** (0x8003) Request to import (attach) a remote USB device. */
    OP_REQ_IMPORT: Buffer;
    /** (0x0003) Reply to import (attach) a remote USB device. */
    OP_REP_IMPORT: Buffer;
    /** (0x00000001) Submit an URB */
    USBIP_CMD_SUBMIT: Buffer;
    /** (0x00000003) Reply for submitting an URB */
    USBIP_RET_SUBMIT: Buffer;
    /** (0x00000002) Unlink an URB */
    USBIP_CMD_UNLINK: Buffer;
    /** (0x00000004) Reply for URB unlink */
    USBIP_RET_UNLINK: Buffer;
}
declare class UsbIpDirections {
    out: number;
    in: number;
}
declare class UsbTransferTypes {
    control: number;
    isochronous: number;
    bulk: number;
    interrupt: number;
}
declare class BmRequestTypes {
    directions: BmRequestDirections;
    types: BmRequestTypeTypes;
    recipients: BmRequestRecipients;
}
declare class BRequests {
    standard: StandardBRequests;
    class: ClassBRequests;
    vendor: VendorBRequests;
}
declare class DescriptorTypes {
    device: number;
    config: number;
    string: number;
    interface: number;
    endpoint: number;
}
declare class InterfaceClasses {
    communicationsAndCdcControl: number;
    hid: number;
}
declare class Parities {
    none: number;
    odd: number;
    even: number;
    mark: number;
    space: number;
}
declare class StopBits {
    one: number;
    onePointFive: number;
    two: number;
}
declare class ErrorCodes {
    ECONNRESET: number;
}
declare class BmRequestDirections {
    deviceToHost: number;
    hostToDevice: number;
}
declare class BmRequestTypeTypes {
    standard: number;
    class: number;
    vendor: number;
    reserved: number;
}
declare class BmRequestRecipients {
    device: number;
    interface: number;
    endpoint: number;
    other: number;
}
declare class StandardBRequests {
    getStatus: number;
    clearFeature: number;
    setFeature: number;
    setAddress: number;
    getDescriptor: number;
    setDescriptor: number;
    getConfiguration: number;
    setConfiguration: number;
    getInterface: number;
    setInterface: number;
    synchFrame: number;
}
declare class ClassBRequests {
    cdc: CdcClassBRequests;
    hid: HidClassBRequests;
}
declare class VendorBRequests {
}
declare class CdcClassBRequests {
    setLineCoding: number;
    setControlLineState: number;
}
declare class HidClassBRequests {
    setIdle: number;
}
