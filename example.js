const process = require('process');
const util = require('util');

const { UsbIpServerSim, SimulatedUsbDevice, usbIpInternals } = require('./index.js');
const { lib } = usbIpInternals;

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
