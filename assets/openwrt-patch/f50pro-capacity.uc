import * as fs from 'fs';

function word(data, offset) {
    if (type(data) != 'string' || length(data) < offset + 4) return null;
    let value = 0;
    for (let n = 0; n < 4; n++) value = value * 256 + ord(substr(data, offset + n, 1));
    return value;
}

function sectors(root, device) {
    if (!match(device || '', /^[A-Za-z0-9_]+$/)) return null;
    let value = trim(fs.readfile(root + '/sys/class/block/' + device + '/size') || '');
    return match(value, /^[0-9]+$/) ? +value / 2 : null;
}

export function capacity(root) {
    root ||= '';
    if (trim(fs.readfile(root + '/etc/mu300/model') || '') != 'f50pro') return {};
    let base = root + '/sys/firmware/devicetree/base';
    let addresses = word(fs.readfile(base + '/#address-cells'), 0) ?? 2;
    let sizes = word(fs.readfile(base + '/#size-cells'), 0) ?? 2;
    let ram = 0;
    if (addresses in [1, 2] && sizes in [1, 2]) {
        let stride = (addresses + sizes) * 4;
        for (let path in fs.glob(base + '/memory*/reg') || []) {
            let data = fs.readfile(path);
            if (type(data) != 'string' || length(data) % stride) continue;
            for (let offset = 0; offset < length(data); offset += stride) {
                let bytes = 0;
                for (let n = 0; n < sizes; n++)
                    bytes = bytes * 4294967296 + word(data, offset + (addresses + n) * 4);
                ram += bytes / 1024;
            }
        }
    }
    let device = replace(trim(fs.readfile(root + '/run/mu300/disk-dev') || '/dev/mmcblk0'), /^\/dev\//, '');
    let part = match(device, /^mmcblk[0-9]+p[0-9]+$/) ? device :
        replace(trim(fs.readfile(root + '/run/mu300-root-dev') || ''), /^\/dev\//, '');
    let disk = replace(device, /p[0-9]+$/, '');
    return { ram_kb: ram > 0 ? ram : null, flash_kb: sectors(root, disk), partition_kb: sectors(root, part) };
};
