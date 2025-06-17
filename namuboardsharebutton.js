// ==UserScript==
// @name         나무위키 게시판 공유 링크 복사 알림
// @namespace    http://tampermonkey.net/
// @version      1.0
// @description  나무위키 게시판 공유 아이콘 마우스 포인터 변경 처리, 링크 복사 시 알림 표시
// @author       R0A
// @match        https://board.namu.wiki/b/*/*
// @grant        GM_addStyle
// @license      MIT
// ==/UserScript==

(function() {
    'use strict';

    GM_addStyle(`
        .article-link i.ion-md-share {
            cursor: pointer;
            transition: opacity 0.2s;
        }
        .article-link i.ion-md-share:hover {
            opacity: 0.7;
        }
        .copy-toast-notification {
            position: fixed;
            bottom: 30px;
            left: 50%;
            transform: translateX(-50%);
            background-color: rgba(0, 0, 0, 0.75);
            color: white;
            padding: 12px 24px;
            border-radius: 25px;
            z-index: 9999;
            font-size: 14px;
            opacity: 0;
            visibility: hidden;
            transition: opacity 0.3s, visibility 0.3s;
        }
        .copy-toast-notification.show {
            opacity: 1;
            visibility: visible;
        }
    `);

    let toastElement = document.createElement('div');
    toastElement.className = 'copy-toast-notification';
    toastElement.textContent = '링크 복사됨';
    document.body.appendChild(toastElement);

    document.addEventListener('click', function(e) {
        if (e.target.matches('.article-link i.ion-md-share')) {
            toastElement.classList.add('show');

            setTimeout(() => {
                toastElement.classList.remove('show');
            }, 1000);
        }
    });
})();