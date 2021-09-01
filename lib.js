
'use strict';

class UsbIpLexicon {
    constructor() {
        this.commands = new UsbIpCommands();
        this.directions = new UsbIpDirections();
        this.transferTypes = new UsbTransferTypes();
        this.bmRequestTypes = new BmRequestTypes();
        this.bRequests = new BRequests();
        this.descriptorTypes = new DescriptorTypes();
        this.interfaceClasses = new InterfaceClasses();
        this.parity = new Parities();
        this.stopBits = new StopBits();
        this.errorCodes = new ErrorCodes();
    }
}

class UsbIpCommands {
    constructor() {
        /** (0x8005) Retrieve the list of exported USB devices. */
        this.OP_REQ_DEVLIST = Buffer.from([0x80, 0x05]);
        /** (0x0005) Reply with the list of exported USB devices. */
        this.OP_REP_DEVLIST = Buffer.from([0x00, 0x05]);

        /** (0x8003) Request to import (attach) a remote USB device. */
        this.OP_REQ_IMPORT = Buffer.from([0x80, 0x03]);
        /** (0x0003) Reply to import (attach) a remote USB device. */
        this.OP_REP_IMPORT = Buffer.from([0x00, 0x03]);

        /** (0x00000001) Submit an URB */
        this.USBIP_CMD_SUBMIT = Buffer.from([0x00, 0x00, 0x00, 0x01]);
        /** (0x00000003) Reply for submitting an URB */
        this.USBIP_RET_SUBMIT = Buffer.from([0x00, 0x00, 0x00, 0x03]);

        /** (0x00000002) Unlink an URB */
        this.USBIP_CMD_UNLINK = Buffer.from([0x00, 0x00, 0x00, 0x02]);
        /** (0x00000004) Reply for URB unlink */
        this.USBIP_RET_UNLINK = Buffer.from([0x00, 0x00, 0x00, 0x04]);
    }
}

class UsbIpDirections {
    constructor() {
        this.out = 0;
        this.in = 1;
    }
}

class UsbTransferTypes {
    constructor() {
        this.control = 0b0000;
        this.isochronous = 0b0001;
        this.bulk = 0b0010;
        this.interrupt = 0b0011;
    }
}

class BmRequestTypes {
    constructor() {
        this.directions = new BmRequestDirections();
        this.types = new BmRequestTypeTypes();
        this.recipients = new BmRequestRecipients();
    }
}

class BmRequestDirections {
    constructor() {
        this.deviceToHost = 0 << 7;
        this.hostToDevice = 1 << 7;
    }
}

class BmRequestTypeTypes {
    constructor() {
        this.standard = 0 << 5;
        this.class = 1 << 5;
        this.vendor = 2 << 5;
        this.reserved = 3 << 5;
    }
}

class BmRequestRecipients {
    constructor() {
        this.device = 0;
        this.interface = 1;
        this.endpoint = 2;
        this.other = 3;
    }
}

class BRequests {
    constructor() {
        this.standard = new StandardBRequests();
        this.class = new ClassBRequests();
        this.vendor = new VendorBRequests();
    }
}

class StandardBRequests {
    constructor() {
        this.getStatus = 0x00;
        this.clearFeature = 0x01;
        this.setFeature = 0x03;
        this.setAddress = 0x05;
        this.getDescriptor = 0x06;
        this.setDescriptor = 0x07;
        this.getConfiguration = 0x08;
        this.setConfiguration = 0x09;
        this.getInterface = 0x0a;
        this.setInterface = 0x0b;
        this.synchFrame = 0x12;
    }
}

class ClassBRequests {
    constructor() {
        this.cdc = new CdcClassBRequests();
        this.hid = new HidClassBRequests();
    }
}

class CdcClassBRequests {
    constructor() {
        this.setLineCoding = 0x20;
        this.setControlLineState = 0x22;
    }
}

class HidClassBRequests {
    constructor() {
        this.setIdle = 0x0a;
    }
}

class VendorBRequests {
    constructor() {

    }
}

class DescriptorTypes {
    constructor() {
        this.device = 0x01;
        this.config = 0x02;
        this.string = 0x03;
        this.interface = 0x04;
        this.endpoint = 0x05;
    }
}

class InterfaceClasses {
    constructor() {
        this.communicationsAndCdcControl = 0x02,
        this.hid = 0x03;
    }
}

class Parities {
    constructor() {
        this.none = 0;
        this.odd = 1;
        this.even = 2;
        this.mark = 3;
        this.space = 4;
    }
}

class StopBits {
    constructor() {
        this.one = 0;
        this.onePointFive = 1;
        this.two = 2;
    }
}

class ErrorCodes {
    constructor() {
        this.ECONNRESET = 54;
    }
}

module.exports = new UsbIpLexicon();
