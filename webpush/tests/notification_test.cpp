#include <webpush/types/credentials.hpp>
#include <webpush/types/notification.hpp>
#include <webpush/types/result.hpp>
#include <webpush/types/subscription.hpp>

#include <userver/utest/utest.hpp>

UTEST(WebPushNotification, DefaultTtl) {
    webpush::Notification n;
    EXPECT_EQ(n.ttl, 3600);
}

UTEST(WebPushSubscription, DefaultEmpty) {
    webpush::Subscription s;
    EXPECT_TRUE(s.endpoint.empty());
    EXPECT_TRUE(s.p256dh.empty());
    EXPECT_TRUE(s.auth.empty());
}

UTEST(WebPushSendResult, Fields) {
    webpush::SendResult r{.status_code = 201, .reason = {}};
    EXPECT_EQ(r.status_code, 201);
    EXPECT_TRUE(r.reason.empty());
}
