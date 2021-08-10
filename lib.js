
'use strict';

class UsbIpLexicon {
    constructor() {
        this.commands = new UsbIpCommands();
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

module.exports = new UsbIpLexicon();
