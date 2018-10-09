<?xml version="1.0" encoding="UTF-8"?>
<ZoneList>
  <Zone name="nl">
    <Policy>default</Policy>
    <SignerConfiguration>signconf.xml</SignerConfiguration>
    <Adapters>
      <Input>
        <Adapter type="File">unsigned.zone</Adapter>
      </Input>
      <Output>
        <Adapter type="File">signed.zone</Adapter>
      </Output>
    </Adapters>
  </Zone>
</ZoneList>
