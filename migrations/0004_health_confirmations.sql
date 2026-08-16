-- CHRTV: offline cần XÁC NHẬN 2 lần probe liên tiếp + reset trạng thái cũ
-- Migration number: 0004
--
-- Trước fix này, MỘT lần probe fail duy nhất là đủ để gán `offline`, kể cả:
--   - 5xx thoáng qua (upstream restart, quá tải vài giây);
--   - 200 + body HTML (trang anti-bot / interstitial chỉ hiện với probe,
--     player thật vẫn xem bình thường);
--   - timeout đúng một nhịp mạng xấu tại colo chạy cron.
-- Chính sách mới: `offline` CHỈ dành cho link thật sự không vô được
-- (host không tới được / im lặng quá 30s / 404-410) và phải fail như vậy
-- 2 lượt probe LIÊN TIẾP mới chốt. Mọi thứ khác là `unknown`.
--
-- `fail_streak` đếm số lượt fail "không vô được" liên tiếp của mỗi kênh;
-- về 0 ngay khi probe thành công. Xoá state cũ để sweep mới xây lại sạch.

ALTER TABLE channel_health ADD COLUMN fail_streak INTEGER NOT NULL DEFAULT 0;
DELETE FROM channel_health;
