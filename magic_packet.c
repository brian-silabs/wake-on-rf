#include "magic_packet.h"

#include <string.h>
#include "sl_common.h"

#define MAX_PAYLOAD_LENGTH              128
#define MAX_EVENT_DATA_LENGTH           20

#define HEADER_802154_LENGTH            9 // Check if better than sizeof
#define HEADER_802154_FC_SHIFT          0
#define HEADER_802154_SEQ_SHIFT         2
#define HEADER_802154_PANID_SHIFT       3
#define HEADER_802154_DEST_SHIFT        5
#define HEADER_802154_SRC_SHIFT         7

#define CRC_802154_LENGTH               2

#define MAGIC_PACKET_FC                 0x9841 //Data Frame, No Security, No Frame Pending, No Ack Required, PanID compressed, 2003 ver, Short Dest Address, Short Source Address
#define MAGIC_PACKET_SRC_ADDRESS        0xFFFF
#define MAGIC_PACKET_DEST_ADDRESS       0xFFFF

#define MAGIC_PACKET_STATUS_BR_SHIFT    0
#define MAGIC_PACKET_STATUS_BR_MASK     0x0001

//Combination of these 3 should not be allowed, hence considered "magic"

// Structure of the 802.15.4 header
typedef struct __attribute__((packed)) { // Only GCC compatible
    uint16_t frameControl;
    uint8_t seqNumber;
    uint16_t panID;
    uint16_t dstAddress;
    uint16_t srcAddress;
} IEEE802154_Header_t;

static uint8_t      filterEnabled_g             = 0;
static uint8_t      amBorderRouter_g            = 0;
static uint8_t      monitoredChannel_g          = 0;
static uint16_t     panId_g                     = 0xFFFF;
static uint8_t      header154LastFC_g           = 0xFF;//Access should be protected
static uint8_t      magicPacketLastFC_g         = 0xFF;//Access should be protected 

static uint8_t      txBuffer[MAX_PAYLOAD_LENGTH] = {0x00};// Temp Tx Buffer
static uint8_t      eventBuffer[MAX_EVENT_DATA_LENGTH] = {0x00}; // Temp event buffer

static uint8_t validateMagicPayloadFC(const MagicPacketPayload_t *magicPayload_a);
static void retransmitMagicPacket(const MagicPacketPayload_t *magicPayload_a);

void enableMagicPacketFilter(MagicPacketEnablePayload_t *enablePayload_a)
{
    panId_g = enablePayload_a->panId;
    monitoredChannel_g = enablePayload_a->channel;
    amBorderRouter_g = enablePayload_a->borderRouter;
    filterEnabled_g = 1;

    memcpy(eventBuffer, (uint8_t *)enablePayload_a, MAGIC_PACKET_PAYLOAD_LENGTH);

    //Optionally perform Radio Init operations (i.e. RX start if required)
    magicPacketCallback(MAGIC_PACKET_EVENT_ENABLED, (void *)eventBuffer);//could be improved to use returned value
}

void disableMagicPacketFilter(void)
{
    filterEnabled_g = 0;
    amBorderRouter_g = 0;
    panId_g = 0xFFFF;

    magicPacketCallback(MAGIC_PACKET_EVENT_DISABLED, NULL);
}

// Forge a magic 802.15.4 packet
void createMagicPacket(uint16_t srcAddress_a, uint16_t destAddress_a, uint16_t panID_a, uint8_t *packetBuffer_a, const MagicPacketPayload_t *magicPayload_a)
{
    IEEE802154_Header_t header;
    // MagicPacketPayload_t magicPayload;

    header.frameControl = MAGIC_PACKET_FC;
    header.seqNumber = ++header154LastFC_g;                       // Sequence number (can be incremented by the caller)
    header.panID = panID_a;                       // Needs to be filled from OT Pan ID
    header.dstAddress = destAddress_a;
    header.srcAddress = srcAddress_a;
    
    // magicPayload.frameCounter = ++magicPacketLastFC_g;
    // magicPayload.status &= ((borderRouter_a << MAGIC_PACKET_STATUS_BR_SHIFT) & MAGIC_PACKET_STATUS_BR_MASK);

    memcpy(packetBuffer_a, (uint8_t *)&header, HEADER_802154_LENGTH);
    memcpy(packetBuffer_a + HEADER_802154_LENGTH, (uint8_t *)magicPayload_a, MAGIC_PACKET_PAYLOAD_LENGTH);
}

// Decode an 802.15.4 packet
MagicPacketError_t decodeMagicPacket(uint8_t *packetBuffer_a)
{
    //IEEE802154_Header_t *header = (IEEE802154_Header_t *)packetBuffer_a;
    IEEE802154_Header_t header;
    header.frameControl =  (*(uint16_t *)(packetBuffer_a + HEADER_802154_FC_SHIFT));
    header.seqNumber =  (*(uint8_t *)(packetBuffer_a + HEADER_802154_SEQ_SHIFT));
    header.panID =  (*(uint16_t *)(packetBuffer_a + HEADER_802154_PANID_SHIFT));
    header.dstAddress =  (*(uint16_t *)(packetBuffer_a + HEADER_802154_DEST_SHIFT));
    header.srcAddress =  (*(uint16_t *)(packetBuffer_a + HEADER_802154_SRC_SHIFT));

    MagicPacketPayload_t *magicPayload = (MagicPacketPayload_t *)(packetBuffer_a + HEADER_802154_LENGTH); // Cast works only if bytes used / should be packed otherwise
    MagicPacketError_t ret = MAGIC_PACKET_SUCCESS;

    if(filterEnabled_g)
    {
      //At this point PanID filtering is on
      header154LastFC_g = header.seqNumber; // Therefore we can update 15.4 Seq no anyway
      if( (MAGIC_PACKET_FC == header.frameControl)
          && (panId_g == header.panID) // Should be always true
          && (MAGIC_PACKET_SRC_ADDRESS == header.srcAddress)
          && (MAGIC_PACKET_DEST_ADDRESS == header.dstAddress)
          && (validateMagicPayloadFC(magicPayload))) // TODO : this may be done later, if we want to retransmit after wake up ?
      {
          // We are good to proceed with a wake up
          if(magicPayload->timeToLive > 0){
              magicPayload->timeToLive--;
              retransmitMagicPacket(magicPayload);
          }
          memcpy(eventBuffer, magicPayload, MAGIC_PACKET_PAYLOAD_LENGTH);//REUSE - Can be put in single static with NULL test on data
          magicPacketCallback(MAGIC_PACKET_EVENT_WAKE_RX, (void*)eventBuffer);
      } else {
          ret = MAGIC_PACKET_ERROR_DROPPED;
      }
    } else {
        ret = MAGIC_PACKET_ERROR_DISABLED;
    }
    return ret;
}

// Decode the application payload
// There is a pb with this if nodes missed the 0xFF
static uint8_t validateMagicPayloadFC(const MagicPacketPayload_t *magicPayload_a) 
{
    //Check and validate Frame counter
    if( (magicPayload_a->frameCounter > magicPacketLastFC_g)
        || ((magicPayload_a->frameCounter >= 0 ) && (magicPacketLastFC_g == 0xFF)))
    {
        return 1;
    } else 
    {
        return 0;
    }
}

static void retransmitMagicPacket(const MagicPacketPayload_t *magicPayload_a)
{
    createMagicPacket(MAGIC_PACKET_SRC_ADDRESS, MAGIC_PACKET_DEST_ADDRESS, panId_g, &txBuffer[1], magicPayload_a);
    txBuffer[0] = HEADER_802154_LENGTH + MAGIC_PACKET_PAYLOAD_LENGTH + CRC_802154_LENGTH; // Separating size management as might be defferent in RAIL or OT
    magicPacketCallback(MAGIC_PACKET_EVENT_TX, (void*)txBuffer);
}

SL_WEAK MagicPacketError_t magicPacketCallback(MagicPacketCallbackEvent_t event, void *data)
{
  (void)event;
  (void)data;
    //Do nothing
  return MAGIC_PACKET_SUCCESS;
}
