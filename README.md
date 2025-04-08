Garlemlia: An Anonymous and Indexable P2P File Sharing Network Based on Modified Garlic Routing and Kademlia

Despite the lack of some comfort features, Garlemlia has proven to be an effective
implementation of an anonymous and private P2P file sharing system. Garlemlia provides
anonymity and privacy through its utilization of Garlic Cast and its data ignorance design.
More than this, though, it has lower cryptographic overhead than I2P due to its utilization
of a hybrid encryption scheme and also provides on-network file indexing. Garlemlia re-
duces the amount of necessary third-party software and components to zero.<br>

This implementation leverages a number of technologies which allow it to not only
function, but to perform quite well. Utilizing Kademlia as the foundational DHT of the
system ensures efficient network routing. Garlic Cast by itself provides an immense boost
to the overall network anonymity and privacy. The modifications we made to our imple-
mentation of Garlic Cast, though, ensure that it is more resistant to network churn and
mitigates MITM attacks. The implementation of data ignorance as the backbone for our
network file system ensures that even if a node knew to whom they were uploading data,
they would not know what data they are uploading. Finally, the implementation of a TOTP
inspired relocation scheme for file metadata and decryption key information makes it even
more difficult and confusing to determine what a user is downloading.

Planned Major Changes:

- [ ] Source Code Cleanup
- [ ] Full Project Comments and Documentation
- [ ] Eclipse Attack Prevention
- [ ] Node Bandwidth Monitoring
- [ ] DoS Attack Prevention
- [ ] Forced Node ID Rotation (File Honeypot Prevention)

Planned Features:

- [ ] TCP Socket Utilization for File Transfers<br>
When performing file chunk downloads, a TCP socket chain should be created. As
of now, the implementation simply utilizes UDP sockets for this. Due to having
no verification in place to determine whether a packet was received, this makes file
chunk transfers in a real environment unstable.
- [ ] Metadata and Key Node Information Relocation<br>
The logic is in place for metadata and key information to relocate itself across the
network, but it is not currently setup to relocate this data. This is despite the file name
node providing the location where this information should be located.
- [ ] Watchdog Threads<br>
Garlemlia does not currently use watchdog threads to ping nodes which have not been
seen from its routing table at regular intervals. This is also not currently configured
for the Garlic Cast implementation, where proxies should expire 10 minutes after
last contact with the sequence number. Implementation of a watchdog thread would
make all of this possible, and could also be used to help with the metadata and key
information relocation.
- [ ] File Indexing Improvement<br>
The current implementation requires the user to search for a file using its exact file
name. It does not provide methods to search by extension or category. The cur-
rent implementation also uses a flood search to index files, but other more efficient
approaches should be tested.
- [ ] Metadata Location Time Period<br>
With the current implementation, a node receives the information of where the meta-
data node will be located for the next 24 hours. This does not cover a scenario where
an incredibly large file is located on nodes with low bandwidth. A system should be
created to handle this problem.
- [ ] API Conversion<br>
Garlemlia would work well as an API that can be called from a separate GUI or web
interface, like qBitTorrent. This would make the application
easier to use and allow others to create their own User Interface (UI).
- [ ] A Graphical User Interface (GUI)<br>
Current interaction with Garlemlia is limited to a badly designed terminal interface.
The user interaction with this implementation was designed with the idea of running
the tests mentioned in Chapter 8, which it does well. This, however, does not mean
that it is a functional interface outside of testing.
