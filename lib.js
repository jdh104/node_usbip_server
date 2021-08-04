
'use strict';

class UsbIpLexicon {
    constructor() {
        this.commands = new UsbIpCommands();
    }
}

class UsbIpCommands {
    constructor() {
        /** Retrieve the list of exported USB devices. */
        this.OP_REQ_DEVLIST = 0x8005;
        /** Reply with the list of exported USB devices. */
        this.OP_REP_DEVLIST = 0x0005;

        /** Request to import (attach) a remote USB device. */
        this.OP_REQ_IMPORT = 0x8003;
        /** Reply to import (attach) a remote USB device. */
        this.OP_REP_IMPORT = 0x0003;

        /** Submit an URB */
        this.USBIP_CMD_SUBMIT = 0x00000001;
        /** Reply for submitting an URB */
        this.USBIP_RET_SUBMIT = 0x00000003;

        /** Unlink an URB */
        this.USBIP_CMD_UNLINK = 0x00000002;
        /** Reply for URB unlink */
        this.USBIP_RET_UNLINK = 0x00000004;
    }
}

module.exports = new UsbIpLexicon();
