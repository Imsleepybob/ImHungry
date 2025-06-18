// ==UserScript==
// @name         나무위키 게시판 확장 기능
// @namespace    http://tampermonkey.net/
// @version      1.0
// @description  페이지네이션 파라미터 제거, 공유 아이콘 UX 개선, 댓글 링크 복사 기능 추가
// @author       R0A
// @match        https://board.namu.wiki/*
// @grant        GM_addStyle
// @license      MIT
// ==/UserScript==

(function() {
    'use strict';

    GM_addStyle(`
        .share-icon {
            cursor: pointer;
            transition: opacity 0.2s;
        }
        .share-icon:hover {
            opacity: 0.7;
        }
        .toast {
            position: fixed; bottom: 30px; left: 50%; transform: translateX(-50%);
            background-color: rgba(0, 0, 0, 0.75); color: white;
            padding: 12px 24px; border-radius: 25px; z-index: 9999;
            font-size: 14px; opacity: 0; visibility: hidden;
            transition: opacity 0.3s, visibility 0.3s;
        }
        .toast.show { opacity: 1; visibility: visible; }
    `);

    let toastElement = null;

    function showToast() {
        if (!toastElement) {
            toastElement = document.createElement('div');
            toastElement.className = 'toast';
            toastElement.textContent = '링크 복사됨';
            document.body.appendChild(toastElement);
        }
        toastElement.classList.add('show');
        setTimeout(() => {
            toastElement.classList.remove('show');
        }, 1000);
    }

    function getCleanUrl() {
        return window.location.origin + window.location.pathname;
    }

    async function copyToClipboard(text) {
        try {
            await navigator.clipboard.writeText(text);
            showToast();
        } catch (err) {
            console.error('클립보드 복사 실패:', err);
        }
    }

    function cleanBoardLinks(node) {
        if (!node.querySelectorAll) return;
        const vrowLinks = node.querySelectorAll('a.vrow[href*="?p="]');
        vrowLinks.forEach(link => {
            const originalHref = link.getAttribute('href');
            if (originalHref && /\/\d+\?p=/.test(originalHref)) {
                link.setAttribute('href', originalHref.split('?')[0]);
            }
        });

        const boardLinks = node.querySelectorAll('a[href*="/b/"][href*="?p="]');
        boardLinks.forEach(link => {
            const originalHref = link.getAttribute('href');
            if (originalHref && /\/\d+\?p=/.test(originalHref)) {
                link.setAttribute('href', originalHref.split('?')[0]);
            }
        });
    }

    function addShareButtonToComment(commentNode) {
        if (commentNode.querySelector('.share-link')) return;
        const rightDiv = commentNode.querySelector('.info-row .right');
        const replyLink = commentNode.querySelector('.reply-link');
        if (rightDiv && replyLink) {
            const shareLink = document.createElement('a');
            shareLink.href = '#';
            shareLink.className = 'share-link';
            shareLink.title = '댓글 링크 복사';
            shareLink.innerHTML = '<span class="icon ion-md-share share-icon"></span>';

            const separator = document.createElement('span');
            separator.className = 'sep';

            rightDiv.insertBefore(shareLink, replyLink);
            rightDiv.insertBefore(separator, replyLink);
        }
    }


    document.addEventListener('click', function(e) {
        const articleShareIcon = e.target.closest('.article-link .share-icon');
        if (articleShareIcon) {
            e.preventDefault();
            copyToClipboard(getCleanUrl());
            return;
        }

        const commentShareLink = e.target.closest('.share-link');
        if (commentShareLink) {
            e.preventDefault();
            const commentWrapper = e.target.closest('.comment-wrapper');
            if (commentWrapper && commentWrapper.id) {
                const commentUrl = getCleanUrl() + '#' + commentWrapper.id;
                copyToClipboard(commentUrl);
            }
        }
    });

    cleanBoardLinks(document.body);

    const mainShareIcon = document.querySelector('.article-link i.ion-md-share');
    if (mainShareIcon) {
        mainShareIcon.className += ' share-icon';
        mainShareIcon.title = '복사';
        document.querySelectorAll('.comment-item').forEach(addShareButtonToComment);
    }

    const observer = new MutationObserver((mutations) => {
        mutations.forEach((mutation) => {
            mutation.addedNodes.forEach((node) => {
                if (node.nodeType !== Node.ELEMENT_NODE) return;

                cleanBoardLinks(node);
                node.querySelectorAll('.comment-item').forEach(addShareButtonToComment);
            });
        });
    });

    observer.observe(document.body, {
        childList: true,
        subtree: true
    });

})();