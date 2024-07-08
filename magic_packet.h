#ifndef MAGIC_PACKET_H
#define MAGIC_PACKET_H

#include <stdint.h>

/**
 * @brief The length of the magic packet payload in bytes.
 *
 * @note This constant defines the expected length of the magic packet payload, which consists of the frame counter, status, and time-to-live fields.
 */
#define MAGIC_PACKET_PAYLOAD_LENGTH     3

/**
 * @brief The default time-to-live (TTL) value for magic packets.
 *
 * @note This constant defines the default TTL value that will be used when creating a magic packet. The TTL is used to limit the number of hops a magic packet can traverse before it is discarded.
 */
#define MAGIC_PACKET_DEFAULT_TTL        0x3


/**
 * @brief Error codes returned by the magic packet decoding functions.
 *
 * @note These error codes are used to indicate the result of decoding a magic packet.
 */
typedef enum {
    MAGIC_PACKET_SUCCESS = 0,        ///< The magic packet was successfully decoded.
    MAGIC_PACKET_ERROR_FATAL,       ///< A generic error occurred, the caller should investigate the source code.
    MAGIC_PACKET_ERROR_DROPPED,     ///< The packet was not a valid magic packet.
    MAGIC_PACKET_ERROR_DUPLICATE,   ///< The packet has already been received.
    MAGIC_PACKET_ERROR_DISABLED     ///< The magic packet filter is not enabled.
} MagicPacketError_t;

/**
 * @brief Enumeration of events that can be reported by the magic packet callback.
 *
 * @note These events are used to indicate the state of the magic packet filter and when a valid magic packet is received.
 *
 * @param MAGIC_PACKET_EVENT_ENABLED   The magic packet filter has been enabled.
 * @param MAGIC_PACKET_EVENT_DISABLED  The magic packet filter has been disabled.
 * @param MAGIC_PACKET_EVENT_WAKE_RX   A valid magic packet has been received.
 * @param MAGIC_PACKET_EVENT_TX        A magic packet transmission has been requested.
 */
typedef enum {
    MAGIC_PACKET_EVENT_ENABLED = 0, // Init 
    MAGIC_PACKET_EVENT_DISABLED, // Deinit
    MAGIC_PACKET_EVENT_WAKE_RX, // Valid Magic packet received
    MAGIC_PACKET_EVENT_TX,// TX requested
} MagicPacketCallbackEvent_t;

/**
 * @brief The payload used to enable the magic packet filter.
 *
 * @param panId The PAN ID to use for the magic packet filter.
 * @param channel The channel to use for the magic packet filter.
 * @param borderRouter A flag indicating if the device is a border router.
 */
typedef struct {
    uint16_t panId;
    uint8_t channel;
    uint8_t borderRouter;
} MagicPacketEnablePayload_t;

/**
 * @brief The payload used in a magic packet.
 *
 * @param frameCounter The frame counter value.
 * @param status The status of the magic packet, with bit 0 indicating if the origin is a border router.
 * @param timeToLive The time-to-live value for the magic packet.
 */
typedef struct {
    uint8_t frameCounter;
    uint8_t status; // Bit 0 indicates if the origin is a border router
    uint8_t timeToLive;
} MagicPacketPayload_t;


/**
 * @brief Enables the magic packet filter with the provided configuration.
 *
 * @param enablePayload_a The configuration parameters for the magic packet filter.
 */
void enableMagicPacketFilter(MagicPacketEnablePayload_t *enablePayload_a);

/**
 * @brief Disables the magic packet filter.
 */
void disableMagicPacketFilter(void);

/**
 * @brief Creates a magic packet with the provided parameters.
 *
 * @param srcAddress_a The source address for the magic packet.
 * @param destAddress_a The destination address for the magic packet.
 * @param panID_a The PAN ID for the magic packet.
 * @param packetBuffer_a The buffer to store the created magic packet.
 * @param magicPayload_a The payload for the magic packet.
 */
void createMagicPacket(uint16_t srcAddress_a, uint16_t destAddress_a, uint16_t panID_a, uint8_t *packetBuffer_a, const MagicPacketPayload_t *magicPayload_a);

/**
 * @brief Decodes a magic packet from the provided buffer.
 *
 * @param packetBuffer The buffer containing the magic packet.
 * @return MagicPacketError_t The result of the decoding operation.
 */
MagicPacketError_t decodeMagicPacket(uint8_t *packetBuffer);


/**
 * @brief Callback function for handling magic packet events.
 *
 * @param event The type of magic packet event that occurred.
 * @param data Pointer to additional data related to the event.
 * @return MagicPacketError_t The result of the event handling operation.
 */
MagicPacketError_t magicPacketCallback(MagicPacketCallbackEvent_t event, void *data);

#endif // MAGIC_PACKET_H
