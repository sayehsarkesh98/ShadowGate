# Edge Manager - سیستم مدیریت ترکیبی

ترکیب Edge Tunnel + سیستم مدیریت حرفه‌ای

## ویژگی‌ها
- ✅ Edge Tunnel اصلی (تغییر نکرده)
- ✅ مدیریت UUID با رابط گرافیکی
- ✅ شمارش بایت (هر ۵ درخواست = ۱KB)
- ✅ محدودیت انقضا
- ✅ محدودیت حجم مصرفی
- ✅ کنترل تعداد اتصالات
- ✅ پنل ادمین حرفه‌ای (فارسی)
- ✅ پنل کاربر برای بررسی وضعیت
- ✅ تولید کانفیگ VLESS با پینگ و وضعیت اتصال
- ✅ لینک اشتراک Edge Tunnel

## نصب سریع

```bash
# ۱. ورود به Cloudflare
wrangler login

# ۲. ادغام فایل‌ها
python merge.py "_worker (1).js" "src/edge-tunnel-managed.js"

# ۳. مقداردهی دیتابیس
wrangler d1 execute edge-manager-db --remote --file=./schema.sql

# ۴. دیپلوی
wrangler deploy
```

## استفاده

### پنل مدیریت (UUID Manager)
آدرس: `https://YOUR-WORKER.workers.dev/manager`
رمز عبور: `admin123`

### پنل وضعیت کاربر
آدرس: `https://YOUR-WORKER.workers.dev/user-status`

### پنل اصلی Edge Tunnel
آدرس: `https://YOUR-WORKER.workers.dev/admin`

### API
- `POST /api/auth/login` - ورود ادمین
- `GET /api/admin/stats` - آمار داشبورد
- `GET /api/admin/users` - لیست کاربران
- `POST /api/admin/users` - ایجاد کاربر
- `DELETE /api/admin/users/:uuid` - حذف کاربر
- `GET /api/admin/users/:uuid/config` - دریافت کانفیگ VLESS
- `GET /api/user/status?uuid=xxx` - بررسی وضعیت کاربر
- `POST /api/user/track` - شمارش پهنای باند

## محاسبه پهنای باند
هر ۵ درخواست = ۱ کیلوبایت

## تنظیمات
در فایل `wrangler.toml` مقادیر زیر را تغییر دهید:
- `HOSTNAME`: آدرس دامنه شما
- `PORT`: پورت اتصال (پیش‌فرض: 443)
- `ADMIN_PASSWORD`: رمز عبور ادمین
