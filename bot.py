"""Telegram-first client experience with private, client-owned agent setup."""

from __future__ import annotations

import math
from html import escape
from typing import Any
from urllib.parse import quote

import asyncio
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update, WebAppInfo
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
)

from adapters import get_adapter
from config import Settings
from database import Database
from security import decrypt_secret

PAGE_SIZE = 8

# Asset type emoji mapping
_TYPE_EMOJI: dict[str, str] = {
    "url": "🌐",
    "web": "🌐",
    "wildcard": "🃏",
    "cidr": "🖧",
    "ip": "🖧",
    "android": "🤖",
    "ios": "🍎",
    "apple": "🍎",
    "mobile": "📱",
    "executable": "⚙️",
    "source": "📦",
    "hardware": "🔧",
    "other": "📦",
}

# Platform badge abbreviations
_PLATFORM_BADGE: dict[str, str] = {
    "hackerone": "H1",
    "intigriti": "IT",
    "yeswehack": "YWH",
    "bugcrowd": "BC",
}


def _asset_emoji(asset_type: str) -> str:
    lower = asset_type.lower()
    for key, emoji in _TYPE_EMOJI.items():
        if key in lower:
            return emoji
    return "🎯"


def _platform_badge(platform: str) -> str:
    key = platform.lower().replace(" ", "").replace("-", "")
    return _PLATFORM_BADGE.get(key, "🔍")


class TelegramNotifier:
    """Owns the shared bot token; it never receives or stores client API keys."""

    def __init__(self, database: Database, settings: Settings) -> None:
        self.database = database
        self.settings = settings
        self.application: Application | None = None

    @property
    def enabled(self) -> bool:
        return bool(self.settings.telegram_bot_token)

    async def start(self) -> None:
        if not self.enabled:
            return
        self.application = (
            Application.builder()
            .token(self.settings.telegram_bot_token)
            .arbitrary_callback_data(True)
            .build()
        )
        self.application.add_handler(CommandHandler("start", self.start_command))
        self.application.add_handler(CommandHandler("help", self.help_command))
        self.application.add_handler(CommandHandler("web", self.web_command))
        self.application.add_handler(CommandHandler("program", self.program_command))
        self.application.add_handler(CommandHandler("program_filter", self.program_filter_command))
        self.application.add_handler(CommandHandler("search", self.search_command))
        self.application.add_handler(CommandHandler("clear", self.clear_command))
        self.application.add_handler(CallbackQueryHandler(self._callback_handler))
        await self.application.initialize()
        await self.application.start()
        await self.application.bot.set_my_commands(
            [
                ("web", "Open private Mini App setup"),
                ("program", "Browse your synced programs & targets"),
                ("program_filter", "Filter targets by asset type"),
                ("clear", "Reset bot UI and start over"),
                ("help", "How private monitoring works"),
            ]
        )
        if self.application.updater:
            await self.application.updater.start_polling(drop_pending_updates=True)

    async def stop(self) -> None:
        if not self.application:
            return
        if self.application.updater:
            await self.application.updater.stop()
        await self.application.stop()
        await self.application.shutdown()
        self.application = None

    async def _reply(self, update: Update, text: str, **kwargs: Any) -> None:
        if update.effective_message:
            await update.effective_message.reply_text(
                text, disable_web_page_preview=True, **kwargs
            )

    # ── Commands ──────────────────────────────────────────────────────────────

    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        if update.effective_chat:
            self.database.register_bot_user(str(update.effective_chat.id))
            
        await self._reply(
            update,
            "👋 <b>Target Monitor</b>'ga xush kelibsiz!\n\n"
            "Endi barcha HackerOne dasturlari markaziy tarzda skaner qilinadi va yangi targetlar shu yerga yuboriladi.\n\n"
            "📋 <b>Buyruqlar:</b>\n"
            "• /program — Dasturlar va targetlarni ko'rish\n"
            "• /search — Barcha targetlar bo'ylab qidirish\n"
            "• /program_filter — Asset turi bo'yicha filter\n"
            "• /help — Yordam",
            parse_mode="HTML",
        )

    async def help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        await self._reply(
            update,
            "🔒 <b>Qanday ishlaydi:</b>\n\n"
            "1. /web orqali sahifani oching\n"
            "2. Platforma API tokenlarini xavfsiz holda kiriting\n"
            "3. Tizim 24/7 rejimida avtomatik ravishda barcha targetlarni kuzatib boradi\n"
            "4. Yangi scope tushsa darhol xabar olasiz\n\n"
            "⚡ <b>Qo'llab-quvvatlanadigan platformalar:</b>\n"
            "• HackerOne (API kalit orqali All Programs)\n"
            "• YesWeHack (JWT Token orqali All Programs)\n"
            "• Intigriti (Bearer token)\n"
            "• Bugcrowd (Public dasturlar uchun token shart emas)\n\n"
            "Xavfsizlik: Tokenlar serverda shifrlangan holda saqlanadi.",
            parse_mode="HTML",
        )

    async def clear_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        if update.effective_message:
            await update.effective_message.reply_text(
                "✅ <b>Tarix tozalandi!</b>\n\nQayta boshlash uchun pastdagi buyruqlardan foydalaning:",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("📋 Dasturlar", callback_data={"a": "prog_list"})],
                    [InlineKeyboardButton("🔍 Filter", callback_data={"a": "filter_menu"})]
                ]),
                parse_mode="HTML"
            )

    async def web_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        chat = update.effective_chat
        if chat is None or chat.type != "private":
            await self._reply(update, "Xavfsizlik uchun /web ni faqat private chatda oching.")
            return
        if not self.settings.mini_app_url or not self.settings.relay_public_url:
            await self._reply(
                update,
                "Mini App hali sozlanmagan. Bot egasiga MINI_APP_URL va RELAY_PUBLIC_URL ni sozlashni ayting.",
            )
            return
        setup_code = self.database.create_web_setup_session(
            str(chat.id), self.settings.web_setup_expire_seconds
        )
        separator = "&" if "?" in self.settings.mini_app_url else "?"
        url = f"{self.settings.mini_app_url}{separator}setup={quote(setup_code)}"
        keyboard = InlineKeyboardMarkup(
            [[InlineKeyboardButton("🔐 Private setup ochish", web_app=WebAppInfo(url=url))]]
        )
        await self._reply(
            update,
            "Bu bir martalik havola 10 daqiqada tugaydi. API kalitingiz yo'q.\n"
            "Kalitlar faqat qurilmangizda saqlanadi.",
            reply_markup=keyboard,
        )

    async def program_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        chat = update.effective_chat
        if chat is None or chat.type != "private":
            await self._reply(update, "/program ni faqat private chatda ishlating.")
            return
        await self._send_program_list(update, str(chat.id))

    async def program_filter_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        chat = update.effective_chat
        if chat is None or chat.type != "private":
            await self._reply(update, "/program_filter ni faqat private chatda ishlating.")
            return
        await self._send_filter_menu(update, str(chat.id), {"p": "GLOBAL"}, context)

    async def search_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        chat = update.effective_chat
        if chat is None or chat.type != "private":
            await self._reply(update, "/search ni faqat private chatda ishlating.")
            return
            
        args = context.args
        if not args:
            await self._reply(update, "Iltimos, qidiruv so'zini kiriting.\nMasalan: <code>/search *vodafone*</code>", parse_mode="HTML")
            return
            
        query = " ".join(args).lower().strip("*")
        
        # Initial searching message
        msg = await self._reply(update, "⏳ <b>Platformalardan qidirilmoqda...</b> (bu biroz vaqt olishi mumkin)", parse_mode="HTML")
        if not msg:
            return
            
        context.user_data["last_search"] = query
        await self._send_search_results(msg, str(chat.id), query, page=0, context=context)

    # ── Search ────────────────────────────────────────────────────────────────
    
    async def _send_search_results(self, message: Any, chat_id: str, query: str, page: int, context: ContextTypes.DEFAULT_TYPE) -> None:
        # Load all programs from cache if valid
        cache_key_all = "all_programs_cache"
        cache_time_key = "all_programs_cache_time"
        
        # Cache for 1 hour (3600 seconds)
        import time
        now = time.time()
        
        if cache_key_all not in context.user_data or now - context.user_data.get(cache_time_key, 0) > 3600:
            conns = self.database.get_user_connections_with_tokens(chat_id)
            if not conns:
                await message.edit_text("Hali birorta ham API ulanish (Connection) sozlanmagan.\nAvval /settings orqali akkauntlaringizni ulang.")
                return
                
            tasks = []
            async def _fetch_from_conn(conn: dict) -> list[dict]:
                adapter_cls = get_adapter(conn["platform"])
                try:
                    token = decrypt_secret(self.settings.fernet(), conn["encrypted_token"]) if conn.get("encrypted_token") else ""
                    return await adapter_cls.fetch_all_programs(
                        conn.get("credential_identifier", ""), 
                        token,
                        timeout_seconds=self.settings.request_timeout_seconds
                    )
                except Exception as e:
                    print(f"Error fetching from {conn['platform']}: {e}")
                    return []

            for conn in conns:
                tasks.append(_fetch_from_conn(conn))
                
            all_programs_raw = await asyncio.gather(*tasks)
            
            merged_programs = []
            for idx, conn_programs in enumerate(all_programs_raw):
                plat = conns[idx]["platform"]
                for p in conn_programs:
                    merged_programs.append({"platform": plat, "handle": p.get("handle", ""), "name": p.get("name", "")})
                    
            context.user_data[cache_key_all] = merged_programs
            context.user_data[cache_time_key] = now
            
        all_programs = context.user_data[cache_key_all]
        
        # Filter based on query
        results = []
        for p in all_programs:
            if query in p["handle"].lower() or query in p["name"].lower():
                results.append(p)
                
        total = len(results)
        if total == 0:
            await message.edit_text(f"🔍 <b>{escape(query)}</b> bo'yicha hech qanday dastur topilmadi.", parse_mode="HTML")
            return
            
        total_pages = max(1, math.ceil(total / PAGE_SIZE))
        targets = results[page * PAGE_SIZE : (page + 1) * PAGE_SIZE]
        
        lines = []
        lines.append(f"🔍 <b>Qidiruv:</b> <code>{escape(query)}</code>")
        lines.append(f"<i>Sahifa {page + 1}/{total_pages}  •  Jami {total} ta dastur</i>\n")
        
        for t in targets:
            badge = _platform_badge(t["platform"])
            n = escape(t.get("name") or t.get("handle") or "Unknown")
            h = escape(t.get("handle") or "")
            if n.lower() != h.lower():
                lines.append(f"🏢 <b>{n}</b> <code>[{badge}]</code>\n   Handle: <code>{h}</code>")
            else:
                lines.append(f"🏢 <b>{n}</b> <code>[{badge}]</code>")
        
        buttons = []
        row = []
        if page > 0:
            row.append(InlineKeyboardButton("◀", callback_data={"a": "srch", "pg": page - 1}))
        if page < total_pages - 1:
            row.append(InlineKeyboardButton("▶", callback_data={"a": "srch", "pg": page + 1}))
        if row:
            buttons.append(row)
            
        await message.edit_text(
            "\n".join(lines),
            reply_markup=InlineKeyboardMarkup(buttons) if buttons else None,
            parse_mode="HTML",
        )

    # ── Program list ──────────────────────────────────────────────────────────

    async def _send_program_list(self, update: Update, chat_id: str, mode: str = "view") -> None:
        programs = self.database.relay_programs(chat_id, limit=10000)
        if not programs:
            await self._reply(
                update,
                "Hali sinxronlangan dastur yo'q.\n/web ni oching va local agentni ishga tushiring.",
            )
            return
            
        platforms = {}
        for p in programs:
            plat = p.get("platform", "HackerOne")
            platforms[plat] = platforms.get(plat, 0) + 1

        action = "plat_filter" if mode == "filter" else "plat_view"
        header = "🔍 <b>Qaysi platformani filter qilasiz?</b>" if mode == "filter" else "📋 <b>Platformani tanlang:</b>"
        
        buttons = []
        for plat, count in platforms.items():
            badge = _platform_badge(plat)
            cb = {"a": action, "plat": plat}
            buttons.append([
                InlineKeyboardButton(f"[{badge}] {plat} ({count} ta dastur)", callback_data=cb)
            ])
            
        await self._reply(
            update,
            header,
            reply_markup=InlineKeyboardMarkup(buttons),
            parse_mode="HTML",
        )

    # ── Callback handler ──────────────────────────────────────────────────────

    async def _callback_handler(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        query = update.callback_query
        if not query or not isinstance(query.data, dict):
            return
        await query.answer()

        data: dict = query.data
        action = data.get("a")
        chat_id = str(query.from_user.id) if query.from_user else None
        if not chat_id:
            return

        try:
            if action == "view":
                await self._cb_show_targets(query, chat_id, data, context)
            elif action == "plat_view":
                await self._cb_show_platform_programs(query, chat_id, data, mode="view")
            elif action == "plat_filter":
                await self._cb_show_platform_programs(query, chat_id, data, mode="filter")
            elif action == "filter_menu":
                await self._send_filter_menu(update, str(chat_id), data, context)
            elif action == "srch":
                page = int(data.get("pg", 0))
                search_query = context.user_data.get("last_search", "")
                await self._send_search_results(query.message, str(chat_id), search_query, page, context)
            elif action == "filter_toggle":
                prog_name = data.get("p", "")
                at = data.get("f", "")
                filters = context.user_data.setdefault(f"filters_{prog_name}", set())
                if at in filters:
                    filters.remove(at)
                else:
                    filters.add(at)
                await self._send_filter_menu(update, chat_id, data, context)
            elif action == "filter_apply":
                data["a"] = "view"
                data["pg"] = 0
                await self._cb_show_targets(query, chat_id, data, context)
            elif action == "filter_clear":
                prog_name = data.get("p", "")
                if f"filters_{prog_name}" in context.user_data:
                    context.user_data[f"filters_{prog_name}"].clear()
                data["a"] = "view"
                data["pg"] = 0
                await self._cb_show_targets(query, chat_id, data, context)
            elif action == "prog_list":
                await self._cb_back_to_list(query, chat_id)
            elif action == "noop":
                pass
        except Exception as exc:
            import logging
            logging.exception("Callback error")
            await query.answer("Xatolik yuz berdi. Qayta urinib ko'ring.", show_alert=True)

    async def _cb_show_targets(self, query: Any, chat_id: str, data: dict, context: ContextTypes.DEFAULT_TYPE) -> None:
        prog_name: str = data.get("p", "")
        page: int = int(data.get("pg", 0))
        
        # Load multi-select filters
        active_filters = context.user_data.get(f"filters_{prog_name}", set())

        db_prog_name = None if prog_name == "GLOBAL" else prog_name

        # If we have filters, we need to fetch all and filter in python, or fetch per type
        # For simplicity, if filters exist, we fetch everything for the program and paginate manually
        if active_filters:
            all_targets, _ = self.database.get_relay_targets(chat_id, db_prog_name, limit=100000)
            filtered_targets = [t for t in all_targets if t["asset_type"] in active_filters]
            total = len(filtered_targets)
            targets = filtered_targets[page * PAGE_SIZE : (page + 1) * PAGE_SIZE]
        else:
            targets, total = self.database.get_relay_targets(
                chat_id, db_prog_name,
                offset=page * PAGE_SIZE,
                limit=PAGE_SIZE,
            )
            
        total_pages = max(1, math.ceil(total / PAGE_SIZE))

        prog_details = self.database.relay_program(chat_id, prog_name) if prog_name != "GLOBAL" else None
        platform = prog_details.get("platform", "HackerOne") if prog_details else "All"
        badge = _platform_badge(platform) if prog_name != "GLOBAL" else "🌐"
        
        filter_label = f"  •  🔍 {len(active_filters)} ta filter" if active_filters else ""

        if not targets and page == 0:
            prog_title = "Barcha dasturlar" if prog_name == "GLOBAL" else prog_name
            msg = (
                f"📌 <b>{prog_title}</b> [{badge}]{filter_label}\n\n"
                "Target topilmadi yoxud tanlangan filterga mos target yo'q."
            )
            await query.edit_message_text(
                msg,
                reply_markup=self._nav_keyboard(data, 0, 1, prog_name, active_filters),
                parse_mode="HTML",
            )
            return

        lines = []
        
        # ── Header ────────────────────────────────────────────────────────────
        prog_title = "Barcha dasturlar" if prog_name == "GLOBAL" else escape(prog_name)
        lines.append(f"<b>📌 {prog_title}</b>  <code>[{badge}]</code>{escape(filter_label)}")
        lines.append(f"<i>Sahifa {page + 1}/{total_pages}  •  Jami {total} ta target</i>")
        lines.append("")

        for i, t in enumerate(targets, start=page * PAGE_SIZE + 1):
            emoji = _asset_emoji(t["asset_type"])
            ident = escape(t["identifier"])
            asset_type = t.get("asset_type", "Other")
            severity = t.get("max_severity")
            coverage = t.get("coverage")
            bounty_eligible = t.get("bounty_eligible")

            # Build tag pills
            tags: list[str] = []
            if severity and severity.lower() not in ("unknown", "none", ""):
                sev_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}.get(severity.lower(), "⚫")
                tags.append(f"{sev_icon} {escape(severity.title())}")
            if coverage and coverage.lower() not in ("unknown", "none", ""):
                # E.g. "Eligible" for submission but maybe ineligible for bounty
                if coverage.lower() == "ineligible":
                    tags.append(f"⛔ {escape(coverage.title())}")
                else:
                    tags.append(f"🛡 {escape(coverage.title())}")
            
            if bounty_eligible is True:
                tags.append("💰 Bounty")
            elif bounty_eligible is False:
                tags.append("🚫 No Bounty")

            # Asset type short label
            type_map = {
                "URL": "URL", "Wildcard": "WLD", "CIDR": "CIDR",
                "Android: Play Store": "APK", "Apple: App Store": "IOS",
                "Hardware/IoT": "HW", "Source Code": "SRC", "SOURCE_CODE": "SRC",
                "Other": "OTH"
            }
            type_short = type_map.get(asset_type, asset_type[:3].upper())

            tag_str = "  ".join(tags) if tags else ""
            
            lines.append(f"{emoji} <code>{ident}</code>")
            
            # Show program name if it's a GLOBAL search
            p_name = t.get("program_name", "Unknown")
            if prog_name == "GLOBAL":
                if tag_str:
                    lines.append(f"   🏢 <b>{escape(p_name)}</b>  |  <code>{type_short}</code>  {tag_str}")
                else:
                    lines.append(f"   🏢 <b>{escape(p_name)}</b>  |  <code>{type_short}</code>")
            else:
                if tag_str:
                    lines.append(f"   <code>{type_short}</code>  {tag_str}")
                else:
                    lines.append(f"   <code>{type_short}</code>")

            # Add separator if not the last item
            if i - (page * PAGE_SIZE + 1) < len(targets) - 1:
                lines.append("==============================")

        # ── Footer ────────────────────────────────────────────────────────────
        if prog_details and "scope_count" in prog_details:
            lines.append("")
            lines.append(f"<i>💡 Jami {prog_details['scope_count']} ta asset</i>")

        await query.edit_message_text(
            "\n".join(lines),
            reply_markup=self._nav_keyboard(data, page, total_pages, prog_name, active_filters),
            parse_mode="HTML",
        )

    async def _send_filter_menu(self, update: Update, chat_id: str, data: dict, context: ContextTypes.DEFAULT_TYPE) -> None:
        prog_name: str = data.get("p", "")
        db_prog_name = None if prog_name == "GLOBAL" else prog_name
        asset_types = self.database.get_relay_target_asset_types(chat_id, db_prog_name)

        if not asset_types:
            msg = "Targetlar topilmadi."
            if update.callback_query:
                await update.callback_query.answer(msg, show_alert=True)
            else:
                await self._reply(update, msg)
            return
            
        active_filters = context.user_data.get(f"filters_{prog_name}", set())

        buttons: list[list[InlineKeyboardButton]] = []
        row: list[InlineKeyboardButton] = []
        for at in asset_types:
            emoji = _asset_emoji(at)
            is_active = at in active_filters
            btn_text = f"✅ {emoji} {at}" if is_active else f"🔲 {emoji} {at}"
            cb = {"a": "filter_toggle", "p": prog_name, "f": at}
            row.append(InlineKeyboardButton(btn_text, callback_data=cb))
            if len(row) == 2:
                buttons.append(row)
                row = []
        if row:
            buttons.append(row)

        buttons.append([
            InlineKeyboardButton(
                "✅ Filterni qo'llash",
                callback_data={"a": "filter_apply", "p": prog_name, "pg": 0},
            ),
        ])
        
        if prog_name == "GLOBAL":
            buttons.append([
                InlineKeyboardButton("❌ Tozalash", callback_data={"a": "filter_clear", "p": prog_name}),
            ])
            msg = "🔍 <b>Barcha dasturlar bo'yicha filter:</b>\nAsset turlarini tanlang:"
        else:
            buttons.append([
                InlineKeyboardButton("❌ Tozalash", callback_data={"a": "filter_clear", "p": prog_name}),
                InlineKeyboardButton("◀ Orqaga", callback_data={"a": "view", "p": prog_name, "pg": 0}),
            ])
            msg = f"🔍 <b>{escape(prog_name)}</b> uchun filter:\nAsset turlarini tanlang:"
            
        if update.callback_query:
            await update.callback_query.edit_message_text(
                msg,
                reply_markup=InlineKeyboardMarkup(buttons),
                parse_mode="HTML",
            )
        else:
            await self._reply(
                update,
                msg,
                reply_markup=InlineKeyboardMarkup(buttons),
                parse_mode="HTML",
            )

    async def _cb_show_platform_programs(self, query: Any, chat_id: str, data: dict, mode: str) -> None:
        plat = data.get("plat", "")
        page = int(data.get("pg", 0))
        programs = self.database.relay_programs(chat_id, limit=10000)
        plat_programs = [p for p in programs if p.get("platform", "HackerOne") == plat]
        
        if not plat_programs:
            await query.answer("Bu platformada dastur topilmadi.", show_alert=True)
            return
            
        action = "filter_menu" if mode == "filter" else "view"
        badge = _platform_badge(plat)
        
        per_page = 40
        total_pages = (len(plat_programs) + per_page - 1) // per_page
        start_idx = page * per_page
        end_idx = start_idx + per_page
        page_programs = plat_programs[start_idx:end_idx]

        header = f"🔍 <b>[{badge}] {plat}</b> — Filterlash uchun dastur tanlang (Sahifa {page+1}/{total_pages}):" if mode == "filter" else f"📋 <b>[{badge}] {plat}</b> — Dasturlar ({len(plat_programs)} ta) (Sahifa {page+1}/{total_pages}):"
        
        buttons = []
        for prog in page_programs:
            prog_name = prog.get("program", "Unknown")
            scope_count = prog.get("scope_count", 0)
            cb = {"a": action, "p": prog_name, "pg": 0, "f": None}
            buttons.append([
                InlineKeyboardButton(f"{prog_name} ({scope_count} target)", callback_data=cb)
            ])
            
        nav_buttons = []
        if page > 0:
            nav_buttons.append(InlineKeyboardButton("⬅️ Oldingi", callback_data={"a": "plat_" + mode, "plat": plat, "pg": page - 1}))
        if page < total_pages - 1:
            nav_buttons.append(InlineKeyboardButton("Keyingi ➡️", callback_data={"a": "plat_" + mode, "plat": plat, "pg": page + 1}))
            
        if nav_buttons:
            buttons.append(nav_buttons)
            
        buttons.append([InlineKeyboardButton("◀ Orqaga", callback_data={"a": "prog_list"})])
        
        await query.edit_message_text(
            header,
            reply_markup=InlineKeyboardMarkup(buttons),
            parse_mode="HTML",
        )

    async def _cb_back_to_list(self, query: Any, chat_id: str) -> None:
        programs = self.database.relay_programs(chat_id, limit=10000)
        if not programs:
            await query.edit_message_text("Sinxronlangan dastur topilmadi.")
            return
            
        platforms = {}
        for p in programs:
            plat = p.get("platform", "HackerOne")
            platforms[plat] = platforms.get(plat, 0) + 1

        buttons = []
        for plat, count in platforms.items():
            badge = _platform_badge(plat)
            cb = {"a": "plat_view", "plat": plat}
            buttons.append([
                InlineKeyboardButton(f"[{badge}] {plat} ({count} ta dastur)", callback_data=cb)
            ])
            
        await query.edit_message_text(
            f"📋 <b>Platformani tanlang:</b>",
            reply_markup=InlineKeyboardMarkup(buttons),
            parse_mode="HTML",
        )

    def _nav_keyboard(
        self,
        data: dict,
        page: int,
        total_pages: int,
        prog_name: str,
        filters: set[str] | None,
    ) -> InlineKeyboardMarkup:
        nav = []
        if page > 0:
            d = data.copy()
            d["pg"] = page - 1
            nav.append(InlineKeyboardButton("⬅️ Oldingi", callback_data=d))
            
        if page < total_pages - 1:
            d = data.copy()
            d["pg"] = page + 1
            nav.append(InlineKeyboardButton("Keyingi ➡️", callback_data=d))

        actions = [
            InlineKeyboardButton("🔙 Orqaga", callback_data={"a": "prog_list"}),
        ]
        
        if filters is not None:
            actions.append(
                InlineKeyboardButton(
                    "🔍 Filter" + (" (On)" if filters else ""),
                    callback_data={"a": "filter_menu", "p": prog_name},
                )
            )

        return InlineKeyboardMarkup([nav, actions])

    # ── Notifications ─────────────────────────────────────────────────────────

    async def send_target(self, target: dict[str, Any], platform_name: str) -> None:
        """Legacy owner-console scanner hook; client keys are never routed here."""
        return

    async def send_client_target(self, chat_id: str, event: dict[str, str]) -> bool:
        if not self.application:
            return False

        emoji = _asset_emoji(event.get("asset_type", ""))
        platform = event.get("platform", "HackerOne")
        badge = _platform_badge(platform)
        event_type = event.get("event_type", "added")

        if event_type == "reintroduced":
            header = "🔄 <b>Target qaytib keldi!</b>"
        else:
            header = "🆕 <b>Yangi target topildi!</b>"

        # Format timestamp nicely (2026-07-23T11:04:02.930042+00:00 -> 2026-07-23 11:04)
        obs = event.get('observed_at', '')
        if 'T' in obs:
            obs = obs.split('.')[0].replace('T', ' ')
        
        text = (
            f"{header}\n\n"
            f"<b>📌 {escape(event['program'])}</b>  <code>[{badge}]</code>\n"
            f"{emoji} <code>{escape(event['identifier'])}</code>\n"
            f"   <code>{escape(event.get('asset_type', 'Other')[:3].upper())}</code>  📂 {escape(event.get('asset_type', 'Other'))}\n"
            f"   🕐 {obs}"
        )
        try:
            await self.application.bot.send_message(chat_id=chat_id, text=text, parse_mode="HTML")
        except Exception:
            return False
        return True

    async def send_client_targets_batch(self, chat_id: str, events: list[dict[str, str]]) -> bool:
        if not self.application or not events:
            return False

        # Group events by program to be safe, though scanner currently batches by program anyway.
        program = events[0].get("program", "Unknown")
        platform = events[0].get("platform", "HackerOne")
        badge = _platform_badge(platform)

        header = f"🆕 <b>Yangi targetlar topildi! ({len(events)} ta)</b>\n\n<b>📌 {escape(program)}</b>  <code>[{badge}]</code>\n"
        
        lines = [header]
        
        # Limit to 15 targets to prevent message too long
        limit = 15
        for i, event in enumerate(events[:limit]):
            emoji = _asset_emoji(event.get("asset_type", ""))
            
            asset_type = event.get('asset_type', 'Other')
            lines.append(f"{emoji} <code>{escape(event['identifier'])}</code>\n   <code>{escape(asset_type[:3].upper())}</code>  📂 {escape(asset_type)}")
            
            if i < min(len(events), limit) - 1:
                lines.append("==============================")
            
        if len(events) > limit:
            lines.append(f"\n<i>... va yana {len(events) - limit} ta target topildi. To'liq ro'yxatni ko'rish uchun miniappga kiring.</i>")
            
        text = "\n".join(lines)
        
        try:
            await self.application.bot.send_message(chat_id=chat_id, text=text, parse_mode="HTML")
        except Exception:
            return False
        return True
