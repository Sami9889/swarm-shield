/**
 * WebRTC P2P Mesh Connection Manager
 *
 * Lifecycle:
 *   1. Register with signaling server via /api/register.
 *   2. Poll /api/peers for new swarm members.
 *   3. For each new peer, create RTCPeerConnection and exchange SDP/ICE via /api/signal.
 *   4. Open a DataChannel for browser-to-browser payload transfer.
 *   5. When fetching data, attempt P2P lookup first with 1.5s timeout.
 *   6. If no peer responds, fall back to server origin (with PoW gate).
 */

class WebRTCMesh {
    /**
     * @param {string} apiBase - The base URL of the API server.
     */
    constructor(apiBase) {
        this.apiBase = apiBase.replace(/\/$/, '');
        this.peerId = null;
        this.peers = new Map(); // peerId -> { connection, dataChannel, iceCandidates }
        this.pollInterval = null;
        this.config = {
            iceServers: [
                { urls: 'stun:stun.l.google.com:19302' },
                { urls: 'stun:stun1.l.google.com:19302' },
            ],
        };
        this.onPeerConnect = null;
        this.onPeerDisconnect = null;
        this.onDataReceive = null;
    }

    /**
     * Starts the mesh: registers with signaling server and begins polling for peers.
     */
    async start() {
        await this.register();
        this.pollPeers();
    }

    /**
     * Registers this client with the signaling server.
     */
    async register() {
        try {
            const res = await fetch(`${this.apiBase}/api/register`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ peerId: this.peerId }),
            });
            const data = await res.json();
            this.peerId = data.peerId;
            console.log(`[Mesh] Registered as ${this.peerId}`);
            return data;
        } catch (err) {
            console.error(`[Mesh] Registration failed: ${err.message}`);
            throw err;
        }
    }

    /**
     * Begins polling for new peers and initiates connections.
     */
    pollPeers() {
        this.pollInterval = setInterval(async () => {
            try {
                const res = await fetch(`${this.apiBase}/api/peers`);
                const data = await res.json();

                for (const peer of data.peers) {
                    if (!this.peers.has(peer.id)) {
                        await this.connectToPeer(peer.id);
                    }
                }

                // Clean up dead peers.
                const currentIds = new Set(data.peers.map(p => p.id));
                for (const [id] of this.peers) {
                    if (!currentIds.has(id)) {
                        this.disconnectPeer(id);
                    }
                }
            } catch (err) {
                console.error(`[Mesh] Peer poll failed: ${err.message}`);
            }
        }, 3000);
    }

    /**
     * Initiates a WebRTC connection to a peer.
     */
    async connectToPeer(remotePeerId) {
        console.log(`[Mesh] Connecting to peer ${remotePeerId}...`);
        const pc = new RTCPeerConnection(this.config);
        const peerState = { connection: pc, dataChannel: null, iceCandidates: [] };

        // Create a data channel for P2P messaging.
        const dc = pc.createDataChannel('swarm-data', {
            ordered: false,
            maxRetransmits: 0,
        });
        peerState.dataChannel = dc;

        this.setupDataChannel(dc, remotePeerId);
        this.setupICECandidateHandler(pc, remotePeerId);

        // Create and send offer.
        const offer = await pc.createOffer();
        await pc.setLocalDescription(offer);

        // Wait for ICE gathering to complete (or timeout).
        await this.waitForICEGathering(pc, 2000);

        try {
            await this.sendSignal(remotePeerId, 'offer', pc.localDescription.sdp);
        } catch (err) {
            console.error(`[Mesh] Failed to send offer to ${remotePeerId}: ${err.message}`);
            pc.close();
            return;
        }

        this.peers.set(remotePeerId, peerState);

        // Listen for incoming answer.
        pc.ondatachannel = (event) => {
            // In case we're the answering peer.
        };

        pc.onconnectionstatechange = () => {
            console.log(`[Mesh] Peer ${remotePeerId} connection state: ${pc.connectionState}`);
            if (pc.connectionState === 'disconnected' || pc.connectionState === 'failed') {
                this.disconnectPeer(remotePeerId);
            }
        };

        // Poll for answer.
        this.pollForAnswer(remotePeerId, pc);
    }

    /**
     * Polls the signaling server for an answer to our offer.
     */
    async pollForAnswer(remotePeerId, pc) {
        const maxAttempts = 30;
        let attempts = 0;

        const interval = setInterval(async () => {
            attempts++;
            try {
                const res = await fetch(`${this.apiBase}/api/peers`);
                const data = await res.json();
                const peer = data.peers.find(p => p.id === remotePeerId);

                if (peer && peer.hasAnswer) {
                    clearInterval(interval);
                    // In a full implementation, we would fetch the actual SDP answer
                    // via /api/signal or WebSocket. For brevity, this is a polling stub.
                    console.log(`[Mesh] Answer received from ${remotePeerId}`);
                }

                if (attempts >= maxAttempts) {
                    clearInterval(interval);
                    console.log(`[Mesh] No answer from ${remotePeerId} after ${maxAttempts} attempts`);
                }
            } catch (err) {
                // Ignore transient errors during polling.
            }
        }, 1000);
    }

    /**
     * Sets up DataChannel event handlers.
     */
    setupDataChannel(dc, peerId) {
        dc.onopen = () => {
            console.log(`[Mesh] DataChannel open with ${peerId}`);
            if (this.onPeerConnect) {
                this.onPeerConnect(peerId);
            }
        };

        dc.onclose = () => {
            console.log(`[Mesh] DataChannel closed with ${peerId}`);
            if (this.onPeerDisconnect) {
                this.onPeerDisconnect(peerId);
            }
        };

        dc.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                console.log(`[Mesh] Received data from ${peerId}:`, data);
                if (this.onDataReceive) {
                    this.onDataReceive(peerId, data);
                }
            } catch (err) {
                console.error(`[Mesh] Failed to parse message from ${peerId}:`, err);
            }
        };

        dc.onerror = (err) => {
            console.error(`[Mesh] DataChannel error with ${peerId}:`, err);
        };
    }

    /**
     * Sets up ICE candidate gathering and signaling.
     */
    setupICECandidateHandler(pc, peerId) {
        pc.onicecandidate = async (event) => {
            if (event.candidate) {
                try {
                    await this.sendSignal(peerId, 'candidate', event.candidate.candidate);
                } catch (err) {
                    console.error(`[Mesh] Failed to send ICE candidate to ${peerId}: ${err.message}`);
                }
            }
        };

        pc.onicegatheringstatechange = () => {
            console.log(`[Mesh] ICE gathering state for ${peerId}: ${pc.iceGatheringState}`);
        };
    }

    /**
     * Waits for ICE gathering to complete with a timeout.
     */
    waitForICEGathering(pc, timeoutMs) {
        return new Promise((resolve) => {
            if (pc.iceGatheringState === 'complete') {
                resolve();
                return;
            }

            const timeout = setTimeout(() => {
                resolve();
            }, timeoutMs);

            pc.onicegatheringstatechange = () => {
                if (pc.iceGatheringState === 'complete') {
                    clearTimeout(timeout);
                    resolve();
                }
            };
        });
    }

    /**
     * Sends a signaling message to the server.
     */
    async sendSignal(peerId, type, sdp = '', candidate = '') {
        const res = await fetch(`${this.apiBase}/api/signal`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                type,
                peerId,
                sdp,
                candidate,
            }),
        });
        if (!res.ok) {
            throw new Error(`Signal failed: ${res.status}`);
        }
    }

    /**
     * Fetches data from the swarm: tries peers first, falls back to origin.
     *
     * @param {string} key - The data key to fetch.
     * @param {number} timeoutMs - P2P timeout before falling back (default 1500ms).
     * @returns {Promise<any>}
     */
    async fetchData(key, timeoutMs = 1500) {
        // Attempt P2P fetch from connected peers.
        const p2pPromise = this.fetchFromPeers(key);
        const timeoutPromise = new Promise((_, reject) => {
            setTimeout(() => reject(new Error('P2P timeout')), timeoutMs);
        });

        try {
            const data = await Promise.race([p2pPromise, timeoutPromise]);
            console.log(`[Mesh] Data retrieved via P2P for key=${key}`);
            return data;
        } catch (err) {
            console.log(`[Mesh] P2P fetch failed for key=${key}, falling back to origin`);
            return this.fetchFromOrigin(key);
        }
    }

    /**
     * Broadcasts data to all connected P2P peers.
     */
    broadcast(data) {
        const message = JSON.stringify(data);
        let sentCount = 0;

        for (const [peerId, state] of this.peers) {
            if (state.dataChannel && state.dataChannel.readyState === 'open') {
                try {
                    state.dataChannel.send(message);
                    sentCount++;
                } catch (err) {
                    console.error(`[Mesh] Failed to broadcast to ${peerId}:`, err);
                }
            }
        }

        console.log(`[Mesh] Broadcasted to ${sentCount} peers`);
        return sentCount;
    }

    /**
     * Attempts to fetch data from connected peers.
     */
    async fetchFromPeers(key) {
        const request = { type: 'fetch', key, timestamp: Date.now() };
        const message = JSON.stringify(request);

        const promises = [];
        for (const [peerId, state] of this.peers) {
            if (state.dataChannel && state.dataChannel.readyState === 'open') {
                const p = new Promise((resolve, reject) => {
                    const handler = (event) => {
                        try {
                            const data = JSON.parse(event.data);
                            if (data.key === key) {
                                state.dataChannel.removeEventListener('message', handler);
                                resolve(data);
                            }
                        } catch (err) {
                            // Ignore non-JSON messages.
                        }
                    };
                    state.dataChannel.addEventListener('message', handler);

                    try {
                        state.dataChannel.send(message);
                    } catch (err) {
                        state.dataChannel.removeEventListener('message', handler);
                        reject(err);
                    }

                    // Per-peer timeout.
                    setTimeout(() => {
                        state.dataChannel.removeEventListener('message', handler);
                        reject(new Error(`Peer ${peerId} timeout`));
                    }, 1400);
                });
                promises.push(p);
            }
        }

        if (promises.length === 0) {
            throw new Error('No connected peers available');
        }

        return Promise.race(promises);
    }

    /**
     * Fetches data from the origin server (fallback).
     */
    async fetchFromOrigin(key) {
        // In a production implementation, this would solve PoW and call /api/data.
        // For this dashboard, we'll just log the fallback.
        console.log(`[Mesh] Fetching ${key} from origin server...`);
        const res = await fetch(`${this.apiBase}/api/data?key=${encodeURIComponent(key)}`);
        if (!res.ok) {
            throw new Error(`Origin fetch failed: ${res.status}`);
        }
        return await res.json();
    }

    /**
     * Disconnects and removes a peer.
     */
    disconnectPeer(peerId) {
        const state = this.peers.get(peerId);
        if (state) {
            if (state.dataChannel) {
                state.dataChannel.close();
            }
            state.connection.close();
            this.peers.delete(peerId);
        }
    }

    /**
     * Stops the mesh and cleans up all connections.
     */
    stop() {
        if (this.pollInterval) {
            clearInterval(this.pollInterval);
            this.pollInterval = null;
        }
        for (const [peerId] of this.peers) {
            this.disconnectPeer(peerId);
        }
        this.peers.clear();
    }
}

// Export for use in dashboard.
window.WebRTCMesh = WebRTCMesh;
