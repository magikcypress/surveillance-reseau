const SpeedTest = require('../speed-test');
const https = require('https');

jest.mock('https');

describe('SpeedTest', () => {
    let speedTest;

    beforeEach(() => {
        speedTest = new SpeedTest();
        jest.clearAllMocks();
    });

    describe('runSpeedTest', () => {
        it('should run both download and upload tests', async () => {
            // Mock successful download test
            const mockDownloadResponse = {
                on: jest.fn((event, callback) => {
                    if (event === 'data') {
                        callback(Buffer.alloc(1024 * 1024)); // 1MB chunk
                    } else if (event === 'end') {
                        callback();
                    }
                })
            };

            // Mock successful upload test
            const mockUploadResponse = {
                on: jest.fn((event, callback) => {
                    if (event === 'end') {
                        callback();
                    }
                })
            };

            https.request.mockImplementation((options, callback) => {
                if (options.path.includes('__down')) {
                    callback(mockDownloadResponse);
                } else {
                    callback(mockUploadResponse);
                }
                return {
                    on: jest.fn(),
                    write: jest.fn(),
                    end: jest.fn()
                };
            });

            const result = await speedTest.runSpeedTest();
            expect(result).toHaveProperty('download');
            expect(result).toHaveProperty('upload');
            expect(result).toHaveProperty('timestamp');
        });

        it('should handle download test error', async () => {
            https.request.mockImplementation((options, callback) => {
                const req = {
                    on: jest.fn((event, callback) => {
                        if (event === 'error') {
                            callback(new Error('Download failed'));
                        }
                    }),
                    end: jest.fn()
                };
                return req;
            });

            await expect(speedTest.runSpeedTest()).rejects.toThrow('Download failed');
        });

        it('should handle upload test error', async () => {
            // Mock successful download but failed upload
            https.request.mockImplementation((options, callback) => {
                if (options.path.includes('__down')) {
                    const res = {
                        on: jest.fn((event, callback) => {
                            if (event === 'data') {
                                callback(Buffer.alloc(1024 * 1024));
                            } else if (event === 'end') {
                                callback();
                            }
                        })
                    };
                    callback(res);
                } else {
                    const req = {
                        on: jest.fn((event, callback) => {
                            if (event === 'error') {
                                callback(new Error('Upload failed'));
                            }
                        }),
                        write: jest.fn(),
                        end: jest.fn()
                    };
                    return req;
                }
            });

            await expect(speedTest.runSpeedTest()).rejects.toThrow('Upload failed');
        });
    });
}); 