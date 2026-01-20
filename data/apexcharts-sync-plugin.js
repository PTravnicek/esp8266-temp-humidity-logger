/**
 * ApexCharts Sync Plugin
 * Synchronizes zoom and pan between multiple charts
 */
(function() {
    'use strict';
    
    // Plugin implementation for chart synchronization
    // This plugin extends ApexCharts to support synchronized zooming/panning
    // The actual sync logic is implemented in app.js using chart events
    
    if (typeof ApexCharts !== 'undefined') {
        // Register plugin if ApexCharts is available
        // The sync functionality is handled via chart events in app.js
        console.log('ApexCharts Sync Plugin loaded');
    }
})();

